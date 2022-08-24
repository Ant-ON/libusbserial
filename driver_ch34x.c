/*
 * libusbserial
 * 
 * Copyright (C) 2019-2022 Anton Prozorov <prozanton@gmail.com>
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

#define CH43X_VENDOR_WCH          0x4348 // WinChipHead
#define CH43X_VENDOR_QIN_HENG     0x1a86 // QinHeng Electronics

#define CH43X_PRODUCT_ID_CH340    0x7523
#define CH43X_PRODUCT_ID_CH340_2  0x7522
#define CH43X_PRODUCT_ID_CH341    0x5523
#define CH43X_PRODUCT_ID_CH34X    0x0445

#define REQTYPE_HOST_FROM_DEVICE  (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_IN)
#define REQTYPE_HOST_TO_DEVICE    (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT)

#define CH34X_REQ_CTL             0xA4
#define CH34X_REQ_WRITE_REG       0x9A
#define CH34X_REQ_READ_REG        0x95

#define CH34X_LCR_ENABLE_RX       0x80
#define CH34X_LCR_ENABLE_TX       0x40
#define CH34X_LCR_MARK_SPACE      0x20
#define CH34X_LCR_PAR_EVEN        0x10
#define CH34X_LCR_ENABLE_PAR      0x08
#define CH34X_LCR_STOP_BITS_2     0x04
#define CH34X_LCR_CS8             0x03
#define CH34X_LCR_CS7             0x02
#define CH34X_LCR_CS6             0x01
#define CH34X_LCR_CS5             0x00

#define CH34X_BIT_RTS             (1 << 6)
#define CH34X_BIT_DTR             (1 << 5)

#define CH34X_STAT_CTS            0x01
#define CH34X_STAT_DSR            0x02
#define CH34X_STAT_RI             0x04
#define CH34X_STAT_DCD            0x08
#define CH34X_STAT_MASK           0x0F

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

static int ch34x_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    return ((CH43X_VENDOR_QIN_HENG == vid)
                && (CH43X_PRODUCT_ID_CH340 == pid ||
                    CH43X_PRODUCT_ID_CH340_2 == pid ||
                    CH43X_PRODUCT_ID_CH341 == pid ||
                    CH43X_PRODUCT_ID_CH34X == pid)) ||
            ((CH43X_VENDOR_WCH == vid)
                && (CH43X_PRODUCT_ID_CH340 == pid));
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

static int ch34x_get_status(struct usbserial_port *port)
{
    unsigned char buffer[2];
    int ret = ch34x_get_req(port, CH34X_REQ_READ_REG, 0x0706, 0, buffer, 2);
    return (ret == 2) ? (buffer[0] & CH34X_STAT_MASK) : -1;
}

static int ch34x_init_reg(struct usbserial_port *port)
{
    /* 
     * Init the device at 9600 bauds
     */

    // DIVISOR + PRESCALER
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x1312, 0xb282) < 0)
        return -1;
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x0f2c, 0x0008) < 0)
        return -1;

    // LCR2 + LCR
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2518, CH34X_LCR_ENABLE_RX | CH34X_LCR_ENABLE_TX | CH34X_LCR_CS8) < 0)
        return -1;

    if(ch34x_get_status(port) < 0)
        return -1;

    // Flow Control
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

    const struct baud_mapping *baud = ch34x_serial_baud(config->baud);
    if (!baud)
        return USBSERIAL_ERROR_UNSUPPORTED_BAUD_RATE;

    unsigned lcr = CH34X_LCR_ENABLE_RX | CH34X_LCR_ENABLE_TX;
    switch (config->stop_bits)
    {
    case USBSERIAL_STOPBITS_1: lcr |= 0; break;
    case USBSERIAL_STOPBITS_1_5: return USBSERIAL_ERROR_UNSUPPORTED_OPERATION;
    case USBSERIAL_STOPBITS_2: lcr |= CH34X_LCR_STOP_BITS_2; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    switch (config->data_bits)
    {
    case USBSERIAL_DATABITS_5: lcr |= CH34X_LCR_CS5; break;
    case USBSERIAL_DATABITS_6: lcr |= CH34X_LCR_CS6; break;
    case USBSERIAL_DATABITS_7: lcr |= CH34X_LCR_CS7; break;
    case USBSERIAL_DATABITS_8: lcr |= CH34X_LCR_CS8; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    switch (config->parity)
    {
    case USBSERIAL_PARITY_NONE: lcr |= 0; break;
    case USBSERIAL_PARITY_ODD: lcr |= CH34X_LCR_ENABLE_PAR; break;
    case USBSERIAL_PARITY_EVEN: lcr |= CH34X_LCR_ENABLE_PAR | CH34X_LCR_PAR_EVEN; break;
    case USBSERIAL_PARITY_MARK: lcr |= CH34X_LCR_ENABLE_PAR | CH34X_LCR_MARK_SPACE; break;
    case USBSERIAL_PARITY_SPACE: lcr |= CH34X_LCR_ENABLE_PAR | CH34X_LCR_MARK_SPACE | CH34X_LCR_PAR_EVEN; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    // DIVISOR + PRESCALER
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x1312, baud->b1312) < 0)
        return -1;
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x0f2c, baud->b0f2c) < 0)
        return -1;
    // LCR2 + LCR
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2518, lcr) < 0)
        return -1;

    if(ch34x_get_status(port) < 0)
        return -1;

    // Flow Control - NONE
    if(ch34x_set_req(port, CH34X_REQ_WRITE_REG, 0x2727, 0x0000) < 0)
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

    return ch34x_set_req(port, CH34X_REQ_CTL, ~((dtr ? CH34X_BIT_DTR : 0) | (rts ? CH34X_BIT_RTS : 0)), 0);
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
