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

#define HC43X_VENDOR_ID 0x1a86
#define HC43X_PRODUCT_ID_HL340 0x7523
#define HC43X_PRODUCT_ID_HL341 0x5523
#define HC43X_PRODUCT_ID_HL34X 0x0445

#define REQTYPE_HOST_FROM_DEVICE (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_IN)
#define REQTYPE_HOST_TO_DEVICE (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT)

#define CH34X_REQ_CTL 0xA4
#define CH34X_REQ_WRITE_REG 0x9A
#define CH34X_REQ_READ_REG  0x95

struct baud_mapping 
{
	int baud;
	unsigned b1312;
	unsigned b0f2c;
};

// Baud rates values
static const struct baud_mapping baud_lookup_table [] = 
{
	{ 300,     0xd980, 0xeb },
	{ 600,     0x6481, 0x76 },
	{ 1200,    0xb281, 0x3b },
	{ 2400,    0xd981, 0x1e },
	{ 4800,    0x6482, 0x0f },
	{ 9600,    0xb282, 0x08 },
	{ 19200,   0xd982, 0x07 },
	{ 38400,   0x6483, 0x07 },
	{ 57600,   0x9883, 0x07 },
	{ 115200,  0xcc83, 0x07 },
	{ 230400,  0xe683, 0x07 },
	{ 460800,  0xf383, 0x07 },
	{ 921600,  0xf387, 0x07 },
	{ 0,       0x0000, 0x00 }
};

// Parity values
#define CH34X_PARITY_NONE  0xc3
#define CH34X_PARITY_ODD   0xcb
#define CH34X_PARITY_EVEN  0xdb
#define CH34X_PARITY_MARK  0xeb
#define CH34X_PARITY_SPACE 0xfb

static int ch34x_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    return ((HC43X_VENDOR_ID == vid)
            && (HC43X_PRODUCT_ID_HL340 == pid || 
				HC43X_PRODUCT_ID_HL341 == pid ||
				HC43X_PRODUCT_ID_HL34X == pid));
}

static const char* ch34x_get_device_name(uint16_t vid, uint16_t pid, uint8_t classs, uint8_t subclass)
{
	return "CH34x";
}

static unsigned int ch34x_get_ports_count(uint16_t vid, uint16_t pid)
{
    return 1;
}

static const struct baud_mapping* ch34x_serial_baud(int baud)
{
	const struct baud_mapping *map = baud_lookup_table;
	while (map->baud)
	{
		if (map->baud == baud)
			return map;
		map++;
	}
	return NULL;
}

static int ch34x_set_req(struct usbserial_port *port, int request, int value, int index)
{
	return libusb_control_transfer(
			port->usb_dev_hdl,
			REQTYPE_HOST_TO_DEVICE,
			request,
			value,
			index,
			NULL,
			0,
			DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static int ch34x_get_req(struct usbserial_port *port, int request, int value, int index, void *data, int len)
{
	int ret;
	
	if (!data)
		len = 0;
	
	return libusb_control_transfer(
			port->usb_dev_hdl,
			REQTYPE_HOST_FROM_DEVICE,
			request,
			value,
			index,
			data,
			len,
			DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static int ch34x_chk_req(struct usbserial_port *port, int request, int value, int len)
{
	unsigned char buffer[len];
	int ret = ch34x_get_req(port, request, value, 0, buffer, len);
	return (ret == len)?0:-1;
}

static int ch34x_init_reg(struct usbserial_port *port)
{
	/* Init the device at 9600 bauds */
	if(ch34x_set_req(port, 0xa1, 0xc29c, 0xb2b9) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_CTL, 0xdf, 0) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_CTL, 0x9f, 0) < 0)
		return -1;
	if(ch34x_chk_req(port, CH34X_REQ_READ_REG, 0x0706, 2))
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2727, 0x0000) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x1312, 0xb282) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x0f2c, 0x0008) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2518, 0x00c3) < 0)
		return -1;
	if(ch34x_chk_req(port, CH34X_REQ_READ_REG, 0x0706, 2))
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2727, 0x0000) < 0)
		return -1;
	return 0;
}

static int ch34x_init(struct usbserial_port *port)
{
    assert(port);

	int ret = usbserial_io_get_endpoint(port, 0);
	if (ret)
		return ret;
	
	ret = ch34x_init_reg(port);
    if (ret)
        goto failed;

    return 0;

failed:
    assert(ret != 0);
	usbserial_io_free_endpoint(port);
    return ret;
}

static int ch34x_deinit(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_free_endpoint(port);
}

static int ch34x_set_config(
        struct usbserial_port *port,
        const struct usbserial_config* config)
{
    assert(port);
    assert(config);

	unsigned parity_byte;

	const struct baud_mapping *baud = ch34x_serial_baud(config->baud);
	if (!baud)
		return USBSERIAL_ERROR_UNSUPPORTED_BAUD_RATE;

	if (config->stop_bits != USBSERIAL_STOPBITS_1)
        return USBSERIAL_ERROR_INVALID_PARAMETER;
	
    switch (config->parity)
    {
    case USBSERIAL_PARITY_NONE: parity_byte = CH34X_PARITY_NONE; break;
    case USBSERIAL_PARITY_ODD: parity_byte = CH34X_PARITY_ODD; break;
    case USBSERIAL_PARITY_EVEN: parity_byte = CH34X_PARITY_EVEN; break;
    case USBSERIAL_PARITY_MARK: parity_byte = CH34X_PARITY_MARK; break;
    case USBSERIAL_PARITY_SPACE: parity_byte = CH34X_PARITY_SPACE; break;

    default:
        return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

	// BaudRate
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x1312, baud->b1312) < 0)
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x0f2c, baud->b0f2c) < 0)
		return -1;
	if(ch34x_chk_req(port, CH34X_REQ_READ_REG, 0x0706, 2))
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2727, 0) < 0)
		return -1;
	// Parity
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2518, parity_byte) < 0)
		return -1;
	if(ch34x_chk_req(port, CH34X_REQ_READ_REG, 0x0706, 2))
		return -1;
	if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2727, 0) < 0)
		return -1;

	return 0;
}

static int ch34x_start_reader(struct usbserial_port *port)
{
    assert(port);
    assert(port->cb_read);

    return usbserial_io_init_bulk_read_transfer(port);
}

static int ch34x_stop_reader(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_cancel_bulk_read_transfer(port);
}

static int ch34x_read(struct usbserial_port *port, void *data, size_t size, int timeout)
{
    assert(port);

    return usbserial_io_bulk_read(port, data, size, timeout);
}

static int ch34x_write(
        struct usbserial_port *port,
        const void *data,
        size_t size)
{
    assert(port);

    return usbserial_io_bulk_write(port, data, size);
}

static int ch34x_purge(
        struct usbserial_port *port,
        int rx,
        int tx)
{
    assert(port);

    return USBSERIAL_ERROR_UNSUPPORTED_OPERATION;
}

static int ch34x_set_dtr_rts(struct usbserial_port *port, int dtr, int rts)
{
    assert(port);

    return ch34x_set_req(port, CH34X_REQ_CTL, ~((dtr ? 1 << 5 : 0) | (rts ? 1 << 6 : 0)), 0);
}

const struct usbserial_driver driver_ch34x =
{
    .check_supported_by_vid_pid = ch34x_check_supported_by_vid_pid,
    .check_supported_by_class = NULL,
    .get_device_name = ch34x_get_device_name,
    .get_ports_count = ch34x_get_ports_count,
    .port_init = ch34x_init,
    .port_deinit = ch34x_deinit,
    .port_set_config = ch34x_set_config,
    .start_reader = ch34x_start_reader,
    .stop_reader = ch34x_stop_reader,
	.read = ch34x_read,
    .write = ch34x_write,
    .purge = ch34x_purge,
	.set_dtr_rts = ch34x_set_dtr_rts,
    .read_data_process = NULL,
};

const struct usbserial_driver *usbserial_driver_ch34x = &driver_ch34x;
