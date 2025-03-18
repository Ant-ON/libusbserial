/*
 * libusbserial
 * 
 * Copyright (C) 2019-2025 Anton Prozorov <prozanton@gmail.com>
 * Copyright (c) 2014-2015 Felix Hädicke
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "io.h"

#include "config.h"
#include "driver.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

static void usbserial_io_default_read_transfer_callback(struct libusb_transfer* transfer)
{
    assert(transfer);

    int ret;
    struct usbserial_port *port = (struct usbserial_port*) transfer->user_data;
    assert(port);

    ret = pthread_mutex_lock(&port->mutex);
    assert(0 == ret);

    if ((LIBUSB_TRANSFER_COMPLETED == transfer->status)
            || (LIBUSB_TRANSFER_TIMED_OUT == transfer->status))
    {
        size_t count = (size_t)transfer->actual_length;
        if (count > 0)
        {
            if (port->driver->read_data_process)
                port->driver->read_data_process(port, transfer->buffer, &count);
            if (count > 0)
                port->cb_read(transfer->buffer, count, port->cb_user_data);
        }
    } else
    {
        if (port->cb_read_error)
            port->cb_read_error(transfer->status, port->cb_user_data);
    }

    if (port->read_cancel_flag)
    {
        libusb_free_transfer(port->read_transfer);
        port->read_transfer = NULL;
    } else
    {
        // Re-submit the transfer
        ret = libusb_submit_transfer(transfer);
        if (ret)
            printf("submitting. error code: %d\n", ret);
    }

    ret = pthread_mutex_unlock(&port->mutex);
    assert(0 == ret);
}

int usbserial_io_init_bulk_read_transfer(struct usbserial_port *port)
{
    assert(port);

    int ret;

    port->read_transfer = libusb_alloc_transfer(0);
    if (!port->read_transfer)
        return USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;

    ret = pthread_mutex_lock(&port->mutex);
    assert(0 == ret);

    port->read_cancel_flag = 0;

    libusb_fill_bulk_transfer(
                port->read_transfer,
                port->usb_dev_hdl,
                port->endp.in,
                port->read_buffer,
                sizeof(port->read_buffer),
                usbserial_io_default_read_transfer_callback,
                port,
                DEFAULT_READ_TIMEOUT_MILLIS);

    ret = pthread_mutex_unlock(&port->mutex);
    assert(0 == ret);
    
    ret = libusb_submit_transfer(port->read_transfer);
    if (ret)
    {
        libusb_free_transfer(port->read_transfer);
        port->read_transfer = NULL;
    }
    return ret;
}

int usbserial_io_cancel_bulk_read_transfer(struct usbserial_port *port)
{
    assert(port);

    int ret;

    if (!port->read_transfer)
        return USBSERIAL_ERROR_ILLEGAL_STATE;

    port->read_cancel_flag = 1;
    
    ret = pthread_mutex_lock(&port->mutex);
    assert(0 == ret);

    libusb_cancel_transfer(port->read_transfer);

    ret = pthread_mutex_unlock(&port->mutex);
    assert(0 == ret);

    return 0;
}

int usbserial_io_bulk_read(struct usbserial_port *port,
        void *data, size_t size, int timeout)
{
    assert(port);
    assert((0 == size) || data);

    int ret;
    int actual_length = 0;

    if (0 == size) return 0;

    ret = libusb_bulk_transfer(
                    port->usb_dev_hdl,
                    port->endp.in,
                    (unsigned char*) data,
                    (int) size,
                    &actual_length,
                    0);
    if (ret < 0)
        return ret;
    return actual_length;
}

int usbserial_io_bulk_write(struct usbserial_port *port,
        const void *data, size_t size)
{
    assert(port);
    assert((!size) || data);

    int ret;
    int actual_length = 0;

    if (!size)
        return 0;

    ret = libusb_bulk_transfer(
                    port->usb_dev_hdl,
                    port->endp.out,
                    (unsigned char*) data,
                    (int) size,
                    &actual_length,
                    0);
    if (!ret || ret == LIBUSB_ERROR_TIMEOUT)
    {
        if (actual_length <= 0 || actual_length == (int)size)
            return ret;

        return usbserial_io_bulk_write(
                    port,
                    ((unsigned char*) data) + actual_length,
                    size - actual_length);
    }
    return ret;
}

int usbserial_io_get_endpoint(struct usbserial_port *port, uint8_t classs, int last)
{
    assert(port);
    
    int ret;
    uint8_t i, j;
    int in_ep_status = 0, out_ep_status = 0;
    struct libusb_config_descriptor *config = NULL;

    ret = libusb_get_active_config_descriptor(port->usb_dev, &config);
    if (ret == LIBUSB_ERROR_NOT_FOUND)
    {
        libusb_set_configuration(port->usb_dev_hdl, 0);
        ret = libusb_get_active_config_descriptor(port->usb_dev, &config);
    }
    if (ret)
        return ret;
    assert(config);

    for (i = 0; i < config->bNumInterfaces; ++i)
    {
        const struct libusb_interface* interface = &config->interface[i];
        assert(interface);
        
        if (!interface->altsetting ||
                (classs && classs != interface->altsetting->bInterfaceClass))
            continue;

        if (classs)
            in_ep_status = out_ep_status = 0;
        if (interface->altsetting->bNumEndpoints > 0)
        {
            for (j = 0; j < interface->altsetting->bNumEndpoints; ++j)
            {
                const struct libusb_endpoint_descriptor* endpoint
                        = &interface->altsetting->endpoint[j];

                if ((endpoint->bmAttributes&0x02) == LIBUSB_TRANSFER_TYPE_BULK)
                {
                    if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN)
                    {
                        if (!in_ep_status || last)
                        {
                            in_ep_status = 1;
                            port->endp.in = endpoint->bEndpointAddress;
                            port->endp.in_if = i;
                        }
                    }
                    else
                    {
                        if (!out_ep_status || last)
                        {
                            out_ep_status = 1;
                            port->endp.out = endpoint->bEndpointAddress;
                            port->endp.out_if = i;
                        }
                    }
                }
            }
        }
        
        if (out_ep_status && in_ep_status)
            break;
    }
    libusb_free_config_descriptor(config);
    
    if (!out_ep_status || ! in_ep_status)
    {
        ret = USBSERIAL_ERROR_UNSUPPORTED_DEVICE;
        goto failed;
    }

    ret = libusb_claim_interface(port->usb_dev_hdl, port->endp.in_if);
    if (ret) 
        goto failed;
    in_ep_status = 2;
    
    if (port->endp.in_if != port->endp.out_if)
    {
        ret = libusb_claim_interface(port->usb_dev_hdl, port->endp.out_if);
        if (ret) 
            goto failed;
        out_ep_status = 2;
    }

    return 0;
    
failed:
    if (in_ep_status == 2)
        libusb_release_interface(port->usb_dev_hdl, port->endp.in_if);
    if (out_ep_status == 2)
        libusb_release_interface(port->usb_dev_hdl, port->endp.out_if);
    memset(&port->endp, 0, sizeof(struct usbserial_endpoints));
    return ret;
}

int usbserial_io_free_endpoint(struct usbserial_port *port)
{
    if (!port->endp.out && !port->endp.in)
        return USBSERIAL_ERROR_ILLEGAL_STATE;
    
    libusb_release_interface(port->usb_dev_hdl, port->endp.in_if);
    if (port->endp.out_if != port->endp.in_if)
        libusb_release_interface(port->usb_dev_hdl, port->endp.out_if);
    memset(&port->endp, 0, sizeof(struct usbserial_endpoints));
    return 0;
}
