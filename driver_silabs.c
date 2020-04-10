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

#define SILABS_VENDOR_ID 0x10c4

#define SILABS_PRODUCT_ID_CP2102 0xea60
#define SILABS_PRODUCT_ID_CP210x 0xea61
#define SILABS_PRODUCT_ID_CP2102N 0xea63 // CP2101-4/CP2102N
#define SILABS_PRODUCT_ID_CP2105 0xea70
#define SILABS_PRODUCT_ID_CP2108 0xea71
#define SILABS_PRODUCT_ID_CP2110 0xea80

#define SILABS_HOST_TO_DEVICE_REQTYPE 0x41

#define SILABS_IFC_REQUEST_CODE 0x00
#define SILABS_BAUDDIV_REQUEST_CODE 0x01
#define SILABS_LINE_CTL_REQUEST_CODE 0x03
#define SILABS_MHS_REQUEST_CODE 0x07
#define SILABS_BAUDRATE_REQUEST_CODE 0x1e
#define SILABS_FLUSH_REQUEST_CODE 0x12

#define SILABS_IFC_UART_ENABLE_VALUE 0x0001
#define SILABS_IFC_UART_DISABLE_VALUE 0x0000

#define SILABS_MHS_MCR_DTR_VALUE 0x0001
#define SILABS_MHS_MCR_RTS_VALUE 0x0002
#define SILABS_MHS_CTRL_DTR_VALUE 0x0100
#define SILABS_MHS_CTLR_RTS_VALUE 0x0200

#define SILABS_FLUSH_RX_VALUE 0x0a
#define SILABS_FLUSH_TX_VALUE 0x05

#define SILABS_MHS_RTS_ON 0x202
#define SILABS_MHS_RTS_OFF 0x200
#define SILABS_MHS_DTR_ON 0x101
#define SILABS_MHS_DTR_OFF 0x100

#define SILABS_BAUDDIV_GEN_FREQ_VALUE 0x384000

#define SILABS_DEFAULT_BAUD_RATE 9600

#define SILABS_READ_ENDPOINT(i) (0x81 + i)
#define SILABS_WRITE_ENDPOINT(i) (0x01 + i)

static const char* SILABS_DEVICE_NAME_CP2102 = "CP2102";
static const char* SILABS_DEVICE_NAME_CP2105 = "CP2105";
static const char* SILABS_DEVICE_NAME_CP2108 = "CP2108";
static const char* SILABS_DEVICE_NAME_CP2110 = "CP2110";
static const char* SILABS_DEVICE_NAME_CP21XX = "CP21XX";

static inline int silabs_set_config(struct usbserial_port *port,
        uint8_t request, uint16_t value)
{
    assert(port);

    return libusb_control_transfer(
                port->usb_dev_hdl,
                SILABS_HOST_TO_DEVICE_REQTYPE,
                request,
                value,
                (uint16_t) port->port_idx,
                NULL,
                0,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static int silabs_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    if (SILABS_VENDOR_ID != vid)
		return 0;

	switch (pid)
	{
	case SILABS_PRODUCT_ID_CP2102:
	case SILABS_PRODUCT_ID_CP210x:
	case SILABS_PRODUCT_ID_CP2102N:
	case SILABS_PRODUCT_ID_CP2105:
	case SILABS_PRODUCT_ID_CP2108:
	case SILABS_PRODUCT_ID_CP2110: return 1;
	default: return 0;
	}
}

static const char* silabs_get_device_name(uint16_t vid, uint16_t pid, uint8_t classs, uint8_t subclass)
{
    assert(SILABS_VENDOR_ID == vid);

    switch (pid)
    {
    case SILABS_PRODUCT_ID_CP2102: return SILABS_DEVICE_NAME_CP2102;
    case SILABS_PRODUCT_ID_CP2105: return SILABS_DEVICE_NAME_CP2105;
    case SILABS_PRODUCT_ID_CP2108: return SILABS_DEVICE_NAME_CP2108;
    case SILABS_PRODUCT_ID_CP2110: return SILABS_DEVICE_NAME_CP2110;
    default: return SILABS_DEVICE_NAME_CP21XX;
    }
}

static unsigned int silabs_get_ports_count(uint16_t vid, uint16_t pid)
{
    assert(SILABS_VENDOR_ID == vid);

    switch (pid)
    {
    case SILABS_PRODUCT_ID_CP2108: return 4;
    default: return 1;
    }
}

static int silabs_port_init(struct usbserial_port *port)
{
    struct silabs_data* pdata;
    int ret;

    assert(port);

    ret = libusb_claim_interface(port->usb_dev_hdl, port->port_idx);
    if (ret)
		return ret;

    ret = silabs_set_config(port, SILABS_IFC_REQUEST_CODE,
                SILABS_IFC_UART_ENABLE_VALUE);
    if (ret)
		goto failed;

    ret = silabs_set_config(port, SILABS_BAUDDIV_REQUEST_CODE,
                SILABS_MHS_MCR_DTR_VALUE
                    | SILABS_MHS_MCR_RTS_VALUE
                    | SILABS_MHS_CTRL_DTR_VALUE
                    | SILABS_MHS_CTLR_RTS_VALUE);
    if (ret)
		goto failed;

    ret = silabs_set_config(port, SILABS_BAUDDIV_REQUEST_CODE,
                SILABS_BAUDDIV_GEN_FREQ_VALUE
                    / SILABS_DEFAULT_BAUD_RATE);
    if (ret)
		goto failed;

	ret = silabs_set_config(port, SILABS_MHS_REQUEST_CODE, 0x00);
    if (ret)
		goto failed;

	port->endp.in = SILABS_READ_ENDPOINT(port->port_idx);
	port->endp.out = SILABS_WRITE_ENDPOINT(port->port_idx);
	port->endp.in_if = port->endp.out_if = port->port_idx;

    return 0;

failed:
    assert(0 != ret);
    libusb_release_interface(port->usb_dev_hdl, port->port_idx);
    return ret;
}

static int silabs_port_deinit(struct usbserial_port *port)
{
    assert(port);

    return libusb_release_interface(port->usb_dev_hdl, port->port_idx);
}

static int silabs_port_set_config(struct usbserial_port *port, const struct usbserial_config* config)
{
    assert(port);
    assert(config);

    int ret;
    unsigned char data[8];
    unsigned char parity_byte, flow_control_byte, data_bits_byte, stop_bits_byte;
    uint32_t baud_le = htole32((uint32_t)config->baud);

    switch (config->parity)
    {
    case USBSERIAL_PARITY_NONE:  parity_byte = 0; break;
    case USBSERIAL_PARITY_ODD:   parity_byte = 1; break;
    case USBSERIAL_PARITY_EVEN:  parity_byte = 2; break;
    case USBSERIAL_PARITY_MARK:  parity_byte = 3; break;
    case USBSERIAL_PARITY_SPACE: parity_byte = 4; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    flow_control_byte = 0; /* Hardware flow control not supported (yet) */

    data_bits_byte = (unsigned char) config->data_bits;

    switch (config->stop_bits)
    {
    case USBSERIAL_STOPBITS_1:
        stop_bits_byte = 0;
        break;
    case USBSERIAL_STOPBITS_1_5:
        stop_bits_byte = 1;
        if (USBSERIAL_DATABITS_5 != config->data_bits)
            return USBSERIAL_ERROR_UNSUPPORTED_OPERATION;
        break;
    case USBSERIAL_STOPBITS_2:
        stop_bits_byte = 1;
        if (USBSERIAL_DATABITS_5 == config->data_bits)
            return USBSERIAL_ERROR_UNSUPPORTED_OPERATION;
        break;

    default:
        return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    memcpy(data, &baud_le, sizeof(baud_le));
    data[4] = parity_byte;
    data[5] = flow_control_byte;
    data[6] = data_bits_byte;
    data[7] = stop_bits_byte;

    ret = libusb_control_transfer(
                port->usb_dev_hdl,
                SILABS_HOST_TO_DEVICE_REQTYPE,
                SILABS_BAUDRATE_REQUEST_CODE,
                0,
                (uint16_t) port->port_idx,
                data,
                sizeof(data),
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
    if (ret > 0)
    {
        if (ret == sizeof(data))
			return 0;
        return USBSERIAL_ERROR_CTRL_CMD_FAILED;
    }
    return ret;
}

static int silabs_start_reader(struct usbserial_port *port)
{
    assert(port);
    assert(port->cb_read);

    return usbserial_io_init_bulk_read_transfer(port);
}

static int silabs_stop_reader(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_cancel_bulk_read_transfer(port);
}

static int silabs_read(struct usbserial_port *port, void *data, size_t size, int timeout)
{
    assert(port);

    return usbserial_io_bulk_read(port, data, size, timeout);
}

static int silabs_write(struct usbserial_port *port, const void *data, size_t size)
{
    assert(port);

    return usbserial_io_bulk_write(port, data, size);
}

static int silabs_purge(struct usbserial_port *port, int rx, int tx)
{
    assert(port);

    uint16_t value =  (rx ? SILABS_FLUSH_RX_VALUE : 0)
					| (tx ? SILABS_FLUSH_TX_VALUE : 0);
    return silabs_set_config(port, SILABS_FLUSH_REQUEST_CODE, value);
}

static int silabs_set_dtr_rts(struct usbserial_port *port, int dtr, int rts)
{
    assert(port);

    uint16_t value =  (dtr?SILABS_MHS_DTR_ON:SILABS_MHS_DTR_OFF)
					| (rts?SILABS_MHS_RTS_ON:SILABS_MHS_RTS_OFF);
	return silabs_set_config(port, SILABS_MHS_REQUEST_CODE, value);
}

const struct usbserial_driver driver_silabs =
{
    .check_supported_by_vid_pid = silabs_check_supported_by_vid_pid,
    .check_supported_by_class = NULL,
    .get_device_name = silabs_get_device_name,
    .get_ports_count = silabs_get_ports_count,
    .port_init = silabs_port_init,
    .port_deinit = silabs_port_deinit,
    .port_set_config = silabs_port_set_config,
    .start_reader = silabs_start_reader,
    .stop_reader = silabs_stop_reader,
	.read = silabs_read,
    .write = silabs_write,
    .purge = silabs_purge,
	.set_dtr_rts = silabs_set_dtr_rts,
    .read_data_process = NULL,
};

const struct usbserial_driver *usbserial_driver_silabs = &driver_silabs;
