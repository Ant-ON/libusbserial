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
#include <endian.h>

#define PROLIFIC_VENDOR_ID                  0x067b
#define PROLIFIC_PRODUCT_ID_PL2303          0x2303 // PL2303HX, HXD, TA, ...
#define PROLIFIC_PRODUCT_ID_PL2303GC        0x23A3
#define PROLIFIC_PRODUCT_ID_PL2303GB        0x23B3
#define PROLIFIC_PRODUCT_ID_PL2303GT        0x23C3
#define PROLIFIC_PRODUCT_ID_PL2303GL        0x23D3
#define PROLIFIC_PRODUCT_ID_PL2303GE        0x23E3
#define PROLIFIC_PRODUCT_ID_PL2303GS        0x23F3

#define PL2303_REQTYPE_HOST2DEVICE_VENDOR   0x40
#define PL2303_REQTYPE_DEVICE2HOST_VENDOR   0xC0
#define PL2303_REQTYPE_HOST2DEVICE          0x21
    
#define PL2303_SET_LINE_CODING              0x20
#define PL2303_GET_LINE_CODING              0x21

#define PL2303_GET_VENDOR                   0x01
#define PL2303_GET_N_VENDOR                 0x81

#define PL2303_SET_VENDOR                    0x01
#define PL2303_SET_N_VENDOR                    0x80

#define PL2303_FLUSH_RX_VALUE               0x08
#define PL2303_FLUSH_TX_VALUE               0x09

#define PL2303_FLUSH_N_VALUE                0x07
#define PL2303_FLUSH_N_VALUE_RX               0x01
#define PL2303_FLUSH_N_VALUE_TX               0x02

#define PL2303_SET_CONTROL                  0x22
#define PL2303_CONTROL_LINE_STATE_RTS         0x2
#define PL2303_CONTROL_LINE_STATE_DTR         0x1

enum pl2303_device_type
{
    PL2303_TYPE_UNKNOWN = 0,
    PL2303_TYPE_H,
    PL2303_TYPE_TA,
    PL2303_TYPE_TB,
    PL2303_TYPE_HX,
    PL2303_TYPE_HXD,
    PL2303_TYPE_HXN
};

struct pl2303_data
{
    enum pl2303_device_type type;
};

static const char *PROLIFIC_DEVICE_NAME_PL2303 = "PL2303";

static inline int pl2303_vendor_write(struct usbserial_port *port,
        uint16_t value, uint16_t index)
{
    struct pl2303_data *pdata = (struct pl2303_data*)port->driver_data;

    return libusb_control_transfer(
                port->usb_dev_hdl,
                PL2303_REQTYPE_HOST2DEVICE_VENDOR,
                pdata->type==PL2303_TYPE_HXN ? PL2303_SET_N_VENDOR : PL2303_SET_VENDOR,
                value,
                index,
                NULL,
                0,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

static inline int pl2303_vendor_read(struct usbserial_port *port, 
        uint16_t value, unsigned char buf[1])
{
    struct pl2303_data *pdata = (struct pl2303_data*)port->driver_data;

    int ret = libusb_control_transfer(
                port->usb_dev_hdl,
                PL2303_REQTYPE_DEVICE2HOST_VENDOR,
                pdata->type==PL2303_TYPE_HXN ? PL2303_GET_N_VENDOR : PL2303_GET_VENDOR,
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

    return pl2303_ctrl(port, PL2303_SET_CONTROL, control, NULL, 0);
}

static int pl2303_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    return ((PROLIFIC_VENDOR_ID == vid) && 
                (PROLIFIC_PRODUCT_ID_PL2303 == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GC == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GB == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GT == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GL == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GE == pid ||
                 PROLIFIC_PRODUCT_ID_PL2303GS == pid));
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

static enum pl2303_device_type pl2303_detect_type(struct libusb_device_descriptor *desc)
{
    /*
     * Detection form Linux kernel driver:
     * https://github.com/torvalds/linux/blob/master/drivers/usb/serial/pl2303.c
     */

    if (desc->bDeviceClass == 0x02 || desc->bMaxPacketSize0 != 0x40)
        return PL2303_TYPE_H;
    
    uint16_t bcdDevice = le16toh(desc->bcdDevice);
    uint16_t bcdUSB = le16toh(desc->bcdUSB);

    switch (bcdUSB) 
    {
        case 0x101:
            /* USB 1.0.1? Let's assume they meant 1.1... */
            break;
        case 0x110:
            switch (bcdDevice) 
            {
                case 0x300:
                    return PL2303_TYPE_HX;
                case 0x400:
                    return PL2303_TYPE_HXD;
                default:
                    return PL2303_TYPE_HX;
            }
            break;
        case 0x200:
            switch (bcdDevice) 
            {
                case 0x100:    /* GC */
                case 0x105:
                    return PL2303_TYPE_HXN;
                case 0x300:    /* GT / TA */
                    return PL2303_TYPE_TA;
                case 0x305:
                case 0x400:    /* GL */
                case 0x405:
                    return PL2303_TYPE_HXN;
                case 0x500:    /* GE / TB */
                    return PL2303_TYPE_TB;
                case 0x505:
                case 0x600:    /* GS */
                case 0x605:
                case 0x700:    /* GR */
                case 0x705:
                    return PL2303_TYPE_HXN;
            }
            break;
    }

    return PL2303_TYPE_UNKNOWN;
}

static int pl2303_port_init(struct usbserial_port *port)
{
    assert(port);

    enum pl2303_device_type type = pl2303_detect_type(&port->usb_dev_desc);
    if (type == PL2303_TYPE_UNKNOWN)
        return -1;

    unsigned char buf[1];
    int ret = usbserial_io_get_endpoint(port, 0);
    if (ret)
        return ret;

    if (type != PL2303_TYPE_HXN)
    {
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
        pl2303_vendor_write(port, 2, type==PL2303_TYPE_H ? 0x24 : 0x44);
        pl2303_vendor_write(port, 3, 0);
        pl2303_set_dtr_rts(port, 0, 0);
        pl2303_vendor_write(port, 0x0505, 0x1311);
    }

    struct pl2303_data* pdata = (struct pl2303_data*) malloc(sizeof(struct pl2303_data));
    if (!pdata)
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto relase_if_and_return;
    }
    pdata->type = type;

    return 0;

relase_if_and_return:
    assert(ret != 0);
    libusb_release_interface(port->usb_dev_hdl, port->port_idx);
    return ret;
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
    uint32_t baud = config->baud; /* we don't check the baudrate to correct value */

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

    baud = htole32(baud); /* to LE */
    memcpy(data, &baud, 4);
    data[4] = stop_bits_byte;
    data[5] = parity_byte;
    data[6] = data_bits_byte;

    ret = pl2303_ctrl(port, PL2303_SET_LINE_CODING, 0, data, sizeof(data));
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

    struct pl2303_data *pdata = (struct pl2303_data*)port->driver_data;
    int p_rx_ret = 0, p_tx_ret = 0;

    if (pdata->type == PL2303_TYPE_HXN)
    {
        int index = 0;
        if (rx) index |= PL2303_FLUSH_N_VALUE_RX;
        if (tx) index |= PL2303_FLUSH_N_VALUE_TX;
        if (index) 
            p_rx_ret = pl2303_vendor_write(port, PL2303_FLUSH_N_VALUE, index);
    } else
    {
        if (rx) p_rx_ret = pl2303_vendor_write(port, PL2303_FLUSH_RX_VALUE, 0);
        if (tx) p_tx_ret = pl2303_vendor_write(port, PL2303_FLUSH_TX_VALUE, 0);
    }

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
