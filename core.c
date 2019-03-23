/*
 * libusbserial
 * 
 * Copyright (C) 2019 Anton Prozorov <prozanton@gmail.com>
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

#include "libusbserial.h"

#include "config.h"
#include "driver.h"
#include "internal.h"

#include <assert.h>
#include <stdlib.h>

struct usbserial_driver *usbserial_driver_ftdi;
struct usbserial_driver *usbserial_driver_silabs;
struct usbserial_driver *usbserial_driver_ch34x;
struct usbserial_driver *usbserial_driver_pl2303;
struct usbserial_driver *usbserial_driver_cdc;

static const struct usbserial_driver* find_driver_for_usb_device(uint16_t vid, uint16_t pid, uint8_t class, uint8_t subclass)
{
	const struct usbserial_driver* drivers[] =
	{
		usbserial_driver_ftdi,
		usbserial_driver_silabs,
		usbserial_driver_ch34x,
		usbserial_driver_pl2303,
		usbserial_driver_cdc,
		NULL
	};

	const struct usbserial_driver **driver = drivers;
	while (*driver)
	{
		if ((*driver)->check_supported_by_vid_pid && (*driver)->check_supported_by_vid_pid(vid, pid))
			return *driver;
		if ((*driver)->check_supported_by_class && (*driver)->check_supported_by_class(class, subclass))
			return *driver;
		driver++;
	}

    return NULL;
}

int usbserial_is_device_supported(uint16_t vid, uint16_t pid, uint8_t class, uint8_t subclass)
{
    return !!find_driver_for_usb_device(vid, pid, class, subclass);
}

const char* usbserial_get_device_name(uint16_t vid, uint16_t pid, uint8_t class, uint8_t subclass)
{
    const struct usbserial_driver* driver = find_driver_for_usb_device(vid, pid, class, subclass);
    if (!driver)
		return NULL;
    return driver->get_device_name(vid, pid, class, subclass);
}

const char* usbserial_get_device_name2(struct usbserial_port *port)
{
    if (!port)
		return NULL;
    return port->driver->get_device_name(
    			port->usb_dev_desc.idVendor, port->usb_dev_desc.idProduct,
				port->usb_dev_desc.bDeviceClass, port->usb_dev_desc.bDeviceSubClass);
}

unsigned int usbserial_get_ports_count(uint16_t vid, uint16_t pid, uint8_t class, uint8_t subclass)
{
    const struct usbserial_driver* driver = find_driver_for_usb_device(vid, pid, class, subclass);
    if (!driver)
		return 0;
    return driver->get_ports_count(vid, pid);
}

int usbserial_port_init(
        struct usbserial_port **out_port,
        libusb_device_handle *usb_dev_hdl,
        unsigned int port_idx,
        usbserial_cb_read_fn cb_read,
        usbserial_cb_error_fn cb_read_error,
        void* cb_user_data)
{
	int ret;
	libusb_device *usb_dev;
	const struct usbserial_driver *driver;
    struct usbserial_port *port = 0;
    struct libusb_device_descriptor usb_dev_desc;
    int mutex_init = 0;

    if (!out_port || !usb_dev_hdl)
		return USBSERIAL_ERROR_INVALID_PARAMETER;

    *out_port = NULL;

    usb_dev = libusb_get_device(usb_dev_hdl);
    if (!usb_dev)
		return USBSERIAL_ERROR_NO_SUCH_DEVICE;

    ret = libusb_get_device_descriptor(usb_dev, &usb_dev_desc);
    if (ret)
		goto failed;

    driver = find_driver_for_usb_device(usb_dev_desc.idVendor, usb_dev_desc.idProduct,
                usb_dev_desc.bDeviceClass, usb_dev_desc.bDeviceSubClass);
    if (!driver)
    {
        ret = USBSERIAL_ERROR_UNSUPPORTED_DEVICE;
        goto failed;
    }
    port = (struct usbserial_port*)calloc(1, sizeof(struct usbserial_port));
    if (!port)
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto failed;
    }

    if (pthread_mutex_init(&port->mutex, NULL))
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto failed;
    }
    mutex_init = 1;

    if (pthread_mutex_lock(&port->mutex))
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto failed;
    }

    port->driver = driver;
	port->usb_dev = usb_dev;
    port->usb_dev_hdl = usb_dev_hdl;
    port->usb_dev_desc = usb_dev_desc;
    port->port_idx = port_idx;
    port->cb_read = cb_read;
    port->cb_read_error = cb_read_error;
    port->cb_user_data = cb_user_data;

    if (pthread_mutex_unlock(&port->mutex))
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto failed;
    }

    ret = driver->port_init(port);
    if (ret) 
		goto failed;

    *out_port = port;

    return 0;

failed:
    assert(0 != ret);

    if (port)
    {
        if (mutex_init)
            pthread_mutex_destroy(&port->mutex);
        free(port);
    }

    return ret;
}

int usbserial_port_deinit(struct usbserial_port *port)
{
    int ret;
	
    if (!port)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
	
    ret = port->driver->port_deinit(port);
    free(port);
    return ret;
}

int usbserial_port_set_config(struct usbserial_port *port, const struct usbserial_config *config)
{
    if (!port || !config)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
    return port->driver->port_set_config(port, config);
}

int usbserial_start_reader(struct usbserial_port *port)
{
    if (!port)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
    if (!port->cb_read)
		return USBSERIAL_ERROR_ILLEGAL_STATE;
    return port->driver->start_reader(port);
}

int usbserial_stop_reader(struct usbserial_port *port)
{
    if (!port)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
    return port->driver->stop_reader(port);
}

int usbserial_write(struct usbserial_port *port, const void *data, size_t bytes_count)
{
    if (!port)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
    return port->driver->write(port, data, bytes_count);
}

int usbserial_purge(struct usbserial_port *port, int rx, int tx)
{
    if (!port)
        return USBSERIAL_ERROR_INVALID_PARAMETER;
    return port->driver->purge(port, rx, tx);
}

int usbserial_set_dtr_rts(struct usbserial_port *port, int dtr, int rts)
{
    if (!port)
		return USBSERIAL_ERROR_INVALID_PARAMETER;
    return port->driver->set_dtr_rts(port, dtr, rts);
}
