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

#include "io.h"
#include "driver.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#define PROLIFIC_VENDOR_ID 0x067b
#define PROLIFIC_PRODUCT_ID_PL2303 0x2303

#define PL2303_REQTYPE_HOST2DEVICE_VENDOR 0x40
#define PL2303_REQTYPE_DEVICE2HOST_VENDOR 0xC0
#define PL2303_REQTYPE_HOST2DEVICE 0x21
	
#define PL2303_REQ_SET_LINE_CODING 0x20
#define PL2303_REQ_GET_LINE_CODING 0x21
#define PL2303_REQ_SET_CONTROL 0x22

#define PL2303_REQ_SET_VENDOR 0x01

#define PL2303_FLUSH_RX_VALUE 0x08
#define PL2303_FLUSH_TX_VALUE 0x09

#define PL2303_CONTROL_LINE_STATE_RTS 0x2
#define PL2303_CONTROL_LINE_STATE_DTR 0x1

static const char *PROLIFIC_DEVICE_NAME_PL2303 = "PL2303";

static inline int pl2303_vendor_write(struct usbserial_port *port,
        uint16_t value, uint16_t index)
{
    return libusb_control_transfer(
                port->usb_dev_hdl,
                PL2303_REQTYPE_HOST2DEVICE_VENDOR,
                PL2303_REQ_SET_VENDOR,
                value,
                index,
                NULL,
                0,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static inline int pl2303_vendor_read(struct usbserial_port *port, 
		uint16_t value, unsigned char buf[1])
{
    int ret = libusb_control_transfer(
                port->usb_dev_hdl,
                PL2303_REQTYPE_DEVICE2HOST_VENDOR,
                PL2303_REQ_SET_VENDOR,
                value,
                0,
                buf,
                1,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
	if (ret == 1)
		return 0;
    if (ret > 0)
        return USBSERIAL_ERROR_CTRL_CMD_FAILED;
    return ret;
}

static inline int pl2303_ctrl(struct usbserial_port *port,
		uint16_t req, uint16_t value,
        void *data, uint16_t size)
{
    return libusb_control_transfer(
                port->usb_dev_hdl,
                PL2303_REQTYPE_HOST2DEVICE,
                req,
                value,
                0,
                data,
                size,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static int pl2303_set_dtr_rts(struct usbserial_port *port, int dtr, int rts)
{
	int control = 0;
	if (dtr) control |= PL2303_CONTROL_LINE_STATE_DTR;
	if (rts) control |= PL2303_CONTROL_LINE_STATE_RTS;

	return pl2303_ctrl(port, PL2303_REQ_SET_CONTROL, control, NULL, 0);
}

static int pl2303_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    return ((PROLIFIC_VENDOR_ID == vid) && (PROLIFIC_PRODUCT_ID_PL2303 == pid));
}

static const char* pl2303_get_device_name(uint16_t vid, uint16_t pid, uint8_t classs, uint8_t subclass)
{
	return PROLIFIC_DEVICE_NAME_PL2303;
}

static unsigned int pl2303_get_ports_count(uint16_t vid, uint16_t pid)
{
    /* Are there any multiport CDC/ACM or Prolific devices out there? */
    return 1;
}

static int pl2303_port_init(struct usbserial_port *port)
{
    assert(port);
	
	unsigned char buf[1];
	int ret = usbserial_io_get_endpoint(port, 0);
	if (ret)
		return ret;
	
	pl2303_vendor_read(port, 0x8484, buf);
	pl2303_vendor_write(port, 0x0404, 0);
	pl2303_vendor_read(port, 0x8484, buf);
	pl2303_vendor_read(port, 0x8383, buf);
	pl2303_vendor_read(port, 0x8484, buf);
	pl2303_vendor_write(port, 0x0404, 1);
	pl2303_vendor_read(port, 0x8484, buf);
	pl2303_vendor_read(port, 0x8383, buf);
	pl2303_vendor_write(port, 0, 1);
	pl2303_vendor_write(port, 1, 0);
	pl2303_vendor_write(port, 2, 0x44);
	pl2303_vendor_write(port, 3, 0);
	pl2303_set_dtr_rts(port, 0, 0);
	pl2303_vendor_write(port, 0x0505, 0x1311);
	
    return 0;
}

static int pl2303_port_deinit(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_free_endpoint(port);
}

static int pl2303_port_set_config(struct usbserial_port *port, const struct usbserial_config* config)
{
    assert(port);
    assert(config);

    int ret;
    unsigned char data[7];
    unsigned char stop_bits_byte, parity_byte, data_bits_byte;
    uint32_t baud_le = htole32((uint32_t)config->baud);

    switch (config->stop_bits)
    {
    case USBSERIAL_STOPBITS_1:   stop_bits_byte = 0; break;
    case USBSERIAL_STOPBITS_1_5: stop_bits_byte = 1; break;
    case USBSERIAL_STOPBITS_2:   stop_bits_byte = 2; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    switch (config->parity)
    {
    case USBSERIAL_PARITY_NONE:  parity_byte = 0; break;
    case USBSERIAL_PARITY_ODD:   parity_byte = 1; break;
    case USBSERIAL_PARITY_EVEN:  parity_byte = 2; break;
    case USBSERIAL_PARITY_MARK:  parity_byte = 3; break;
    case USBSERIAL_PARITY_SPACE: parity_byte = 4; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    data_bits_byte = (unsigned char) config->data_bits;

    memcpy(data, &baud_le, sizeof(baud_le));
    data[4] = stop_bits_byte;
    data[5] = parity_byte;
    data[6] = data_bits_byte;

	ret = pl2303_ctrl(port, PL2303_REQ_SET_LINE_CODING, 0, data, sizeof(data));
	if (ret == sizeof(data)) 
		return 0;
    if (ret > 0)
		return USBSERIAL_ERROR_CTRL_CMD_FAILED;
	return ret;
}

static int pl2303_start_reader(struct usbserial_port *port)
{
    assert(port);
    assert(port->cb_read);

    return usbserial_io_init_bulk_read_transfer(port);
}

static int pl2303_stop_reader(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_cancel_bulk_read_transfer(port);
}

static int pl2303_read(
        struct usbserial_port *port,
        void *data,
        size_t size,
		int timeout)
{
    assert(port);

    return usbserial_io_bulk_read(port, data, size, timeout);
}

static int pl2303_write(
        struct usbserial_port *port,
        const void *data,
        size_t size)
{
    assert(port);

    return usbserial_io_bulk_write(port, data, size);
}

static int pl2303_purge(struct usbserial_port *port, int rx, int tx)
{
    assert(port);

	int p_rx_ret = 0, p_tx_ret = 0;

	if (rx) p_rx_ret = pl2303_vendor_write(port, PL2303_FLUSH_RX_VALUE, 0);
	if (tx) p_tx_ret = pl2303_vendor_write(port, PL2303_FLUSH_TX_VALUE, 0);
	return p_rx_ret ? p_rx_ret : p_tx_ret;
}

const struct usbserial_driver driver_pl2303 =
{
    .check_supported_by_vid_pid = pl2303_check_supported_by_vid_pid,
    .check_supported_by_class = NULL,
    .get_device_name = pl2303_get_device_name,
    .get_ports_count = pl2303_get_ports_count,
    .port_init = pl2303_port_init,
    .port_deinit = pl2303_port_deinit,
    .port_set_config = pl2303_port_set_config,
    .start_reader = pl2303_start_reader,
    .stop_reader = pl2303_stop_reader,
	.read = pl2303_read,
    .write = pl2303_write,
    .purge = pl2303_purge,
	.set_dtr_rts = pl2303_set_dtr_rts,
    .read_data_process = NULL,
};

const struct usbserial_driver *usbserial_driver_pl2303 = &driver_pl2303;
