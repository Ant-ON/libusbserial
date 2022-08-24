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

#define FTDI_VENDOR_ID                    0x0403

#define FTDI_PRODUCT_ID_FT232R            0x6001
#define FTDI_PRODUCT_ID_FT232R_FAKE       0x0000
#define FTDI_PRODUCT_ID_FT232RL           0xFBFA
#define FTDI_PRODUCT_ID_FT2232            0x6010
#define FTDI_PRODUCT_ID_FT4232H           0x6011
#define FTDI_PRODUCT_ID_FT232H            0x6014
#define FTDI_PRODUCT_ID_FT231X            0x6015
#define FTDI_PRODUCT_ID_STK500            0xfa33
#define FTDI_PRODUCT_ID_OPENMOKO          0x5118 /* FT2232 */
#define FTDI_PRODUCT_ID_TUMPA             0x8A98 /* FT2232 */
#define FTDI_PRODUCT_ID_KTLINK            0xBBE2 /* FT2232 */
#define FTDI_PRODUCT_ID_JTAGKEY           0xCFF8 /* FT2232 */

#define FTDI_SIO_RESET                    0
#define FTDI_SIO_MODEM_CTRL               1
#define FTDI_SIO_SET_BAUD_RATE            3
#define FTDI_SIO_SET_CONFIG               4

#define FTDI_SIO_RESET_PURGE_RX           1
#define FTDI_SIO_RESET_PURGE_TX           2

#define FTDI_SIO_SET_DTR_MASK             0x1
#define FTDI_SIO_SET_DTR_HIGH             (1 | (FTDI_SIO_SET_DTR_MASK << 8))
#define FTDI_SIO_SET_DTR_LOW              (0 | (FTDI_SIO_SET_DTR_MASK << 8))
#define FTDI_SIO_SET_RTS_MASK             0x2
#define FTDI_SIO_SET_RTS_HIGH             (2 | (FTDI_SIO_SET_RTS_MASK << 8))
#define FTDI_SIO_SET_RTS_LOW              (0 | (FTDI_SIO_SET_RTS_MASK << 8))

#define FTDI_DEVICE_IN_REQTYPE            LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | 0x80
#define FTDI_DEVICE_OUT_REQTYPE           LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE

#define FTDI_MODEM_STATUS_BYTES_COUNT     2

#define FTDI_PARITY_CONFIG_VALUE_SHIFT    8
#define FTDI_STOP_BITS_CONFIG_VALUE_SHIFT 11

#define FTDI_PARITY_NONE_CONFIG_VALUE     (0x00 << FTDI_PARITY_CONFIG_VALUE_SHIFT)
#define FTDI_PARITY_ODD_CONFIG_VALUE      (0x01 << FTDI_PARITY_CONFIG_VALUE_SHIFT)
#define FTDI_PARITY_EVEN_CONFIG_VALUE     (0x02 << FTDI_PARITY_CONFIG_VALUE_SHIFT)
#define FTDI_PARITY_MARK_CONFIG_VALUE     (0x03 << FTDI_PARITY_CONFIG_VALUE_SHIFT)
#define FTDI_PARITY_SPACE_CONFIG_VALUE    (0x04 << FTDI_PARITY_CONFIG_VALUE_SHIFT)

#define FTDI_STOP_BITS_1_CONFIG_VALUE     (0x00 << FTDI_STOP_BITS_CONFIG_VALUE_SHIFT)
#define FTDI_STOP_BITS_1_5_CONFIG_VALUE   (0x01 << FTDI_STOP_BITS_CONFIG_VALUE_SHIFT)
#define FTDI_STOP_BITS_2_CONFIG_VALUE     (0x02 << FTDI_STOP_BITS_CONFIG_VALUE_SHIFT)

#define FTDI_SET_MODEM_CTRL_DEFAULT1      0x0101

#define FTDI_READ_ENDPOINT(i)             (0x81 + 2 * i)
#define FTDI_WRITE_ENDPOINT(i)            (0x02 + 2 * i)

static const char* FTDI_DEVICE_NAME_FT232R   = "FT232R";
static const char* FTDI_DEVICE_NAME_FT232RL  = "FT232RL";
static const char* FTDI_DEVICE_NAME_FT2232   = "FT2232";
static const char* FTDI_DEVICE_NAME_FT4232H  = "FT4232H";
static const char* FTDI_DEVICE_NAME_FT232H   = "FT232H";
static const char* FTDI_DEVICE_NAME_FT231X   = "FT231X";
static const char* FTDI_DEVICE_NAME_STK500   = "STK500";
static const char* FTDI_DEVICE_NAME_OPENMOKO = "OPENMOKO";
static const char* FTDI_DEVICE_NAME_TUMPA    = "TUMPA";
static const char* FTDI_DEVICE_NAME_KTLINK   = "KTLINK";
static const char* FTDI_DEVICE_NAME_JTAGKEY  = "JTAGKEY";
static const char* FTDI_DEVICE_NAME_GENERIC  = "FTDI";

enum ftdi_device_type
{
    FTDI_DEVICE_TYPE_4232H,
    FTDI_DEVICE_TYPE_2232,
    FTDI_DEVICE_TYPE_232H,
    FTDI_DEVICE_TYPE_OTHER
};

struct ftdi_data
{
    enum ftdi_device_type device_type;
    uint16_t control_idx;
    size_t max_packet_size;
};

struct ftdi_baud_data
{
    int baud;
    uint16_t value;
};

// Baud rates values
static const struct ftdi_baud_data baud_lookup_table [] = 
{
    { 300,     0x2710 },
    { 600,     0x1388 },
    { 1200,    0x09c4 },
    { 2400,    0x04e2 },
    { 4800,    0x0271 },
    { 9600,    0x4138 },
    { 19200,   0x809c },
    { 38400,   0xc04e },
    { 57600,   0x0034 },
    { 115200,  0x001a },
    { 230400,  0x000d },
    { 460800,  0x4006 },
    { 921600,  0x8003 },
    { 0,       0x0000 }
};

static const struct ftdi_baud_data* ftdi_serial_baud(int baud)
{
    const struct ftdi_baud_data *map = baud_lookup_table;
    while (map->baud)
    {
        if (map->baud == baud)
            return map;
        map++;
    }
    return NULL;
}

static inline int ftdi_ctrl(struct usbserial_port *port,
        uint16_t req, uint16_t sio, uint16_t control_idx)
{
    return libusb_control_transfer(
                port->usb_dev_hdl,
                FTDI_DEVICE_OUT_REQTYPE,
                req,
                sio,
                control_idx,
                NULL,
                0,
                DEFAULT_CONTROL_TIMEOUT_MILLIS);
}

int ftdi_check_supported_by_vid_pid(uint16_t vid, uint16_t pid)
{
    if (FTDI_VENDOR_ID != vid)
        return 0;

    switch (pid)
    {
    case FTDI_PRODUCT_ID_FT232R:
    case FTDI_PRODUCT_ID_FT232R_FAKE:
    case FTDI_PRODUCT_ID_FT232RL:
    case FTDI_PRODUCT_ID_FT2232:
    case FTDI_PRODUCT_ID_FT4232H:
    case FTDI_PRODUCT_ID_FT231X:
    case FTDI_PRODUCT_ID_FT232H:
    case FTDI_PRODUCT_ID_STK500:
    case FTDI_PRODUCT_ID_OPENMOKO:
    case FTDI_PRODUCT_ID_TUMPA:
    case FTDI_PRODUCT_ID_KTLINK:
    case FTDI_PRODUCT_ID_JTAGKEY:
        return 1;

    default: return 0;
    }
}

static const char* ftdi_get_device_name(uint16_t vid, uint16_t pid, uint8_t classs, uint8_t subclass)
{
    assert(FTDI_VENDOR_ID == vid);

    switch (pid)
    {
    case FTDI_PRODUCT_ID_FT232R:
    case FTDI_PRODUCT_ID_FT232R_FAKE: return FTDI_DEVICE_NAME_FT232R;
    case FTDI_PRODUCT_ID_FT2232: return FTDI_DEVICE_NAME_FT2232;
    case FTDI_PRODUCT_ID_FT4232H: return FTDI_DEVICE_NAME_FT4232H;
    case FTDI_PRODUCT_ID_FT232H: return FTDI_DEVICE_NAME_FT232H;        
    case FTDI_PRODUCT_ID_FT231X: return FTDI_DEVICE_NAME_FT231X;
    case FTDI_PRODUCT_ID_FT232RL: return FTDI_DEVICE_NAME_FT232RL;
    case FTDI_PRODUCT_ID_STK500: return FTDI_DEVICE_NAME_STK500;
    case FTDI_PRODUCT_ID_OPENMOKO: return FTDI_DEVICE_NAME_OPENMOKO;
    case FTDI_PRODUCT_ID_TUMPA: return FTDI_DEVICE_NAME_TUMPA;
    case FTDI_PRODUCT_ID_KTLINK: return FTDI_DEVICE_NAME_KTLINK;
    case FTDI_PRODUCT_ID_JTAGKEY: return FTDI_DEVICE_NAME_JTAGKEY;

    default: return FTDI_DEVICE_NAME_GENERIC;
    }
}

static unsigned int ftdi_get_ports_count(uint16_t vid, uint16_t pid)
{
    assert(FTDI_VENDOR_ID == vid);

    switch (pid)
    {
    case FTDI_PRODUCT_ID_OPENMOKO:
    case FTDI_PRODUCT_ID_TUMPA:
    case FTDI_PRODUCT_ID_KTLINK:
    case FTDI_PRODUCT_ID_JTAGKEY:
    case FTDI_PRODUCT_ID_FT2232: return 2;
    case FTDI_PRODUCT_ID_FT4232H: return 4;

    default: return 1;
    }
}

static int ftdi_port_init(struct usbserial_port *port)
{
    struct ftdi_data* pdata;
    int ret;
    enum ftdi_device_type device_type;
    uint16_t control_idx;
    unsigned int max_packet_size;

    assert(port);

    switch (port->usb_dev_desc.idProduct)
    {
    case FTDI_PRODUCT_ID_OPENMOKO:
    case FTDI_PRODUCT_ID_TUMPA:
    case FTDI_PRODUCT_ID_KTLINK:
    case FTDI_PRODUCT_ID_JTAGKEY:
    case FTDI_PRODUCT_ID_FT2232:
        device_type = FTDI_DEVICE_TYPE_2232;
        control_idx = port->port_idx + 1;
        break;
    case FTDI_PRODUCT_ID_FT4232H:
        device_type = FTDI_DEVICE_TYPE_4232H;
        control_idx = port->port_idx + 1;
        break;

    default:
        device_type = FTDI_DEVICE_TYPE_OTHER;
        if (port->port_idx) 
            return USBSERIAL_ERROR_INVALID_PORT_IDX;
        control_idx = 0;
    }

    switch (port->usb_dev_desc.idProduct)
    {
    //case FTDI_PRODUCT_ID_FT232H:    
    //case FTDI_PRODUCT_ID_FT2232:
    //case FTDI_PRODUCT_ID_FT4232H: max_packet_size = 512; break;
    default: max_packet_size = 64; break;
    }

    ret = libusb_claim_interface(port->usb_dev_hdl, port->port_idx);
    if (ret) 
        return ret;

    ret = ftdi_ctrl(port, FTDI_SIO_RESET, 0x00, control_idx);
    if (ret) 
        goto relase_if_and_return;

    ret = ftdi_ctrl(port, FTDI_SIO_MODEM_CTRL, FTDI_SET_MODEM_CTRL_DEFAULT1, control_idx);
    if (ret) 
        goto relase_if_and_return;
    
    pdata = (struct ftdi_data*) malloc(sizeof(struct ftdi_data));
    if (!pdata)
    {
        ret = USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;
        goto relase_if_and_return;
    }
    pdata->device_type = device_type;
    pdata->control_idx = control_idx;
    pdata->max_packet_size = max_packet_size;
    
    port->driver_data = pdata;

    port->endp.in = FTDI_READ_ENDPOINT(port->port_idx);
    port->endp.out = FTDI_WRITE_ENDPOINT(port->port_idx);
    port->endp.in_if = port->endp.out_if = port->port_idx;
    
    return 0;

relase_if_and_return:
    assert(ret != 0);
    libusb_release_interface(port->usb_dev_hdl, port->port_idx);
    return ret;
}

static int ftdi_port_deinit(struct usbserial_port *port)
{
    assert(port);

    if (!port->driver_data)
        return USBSERIAL_ERROR_ILLEGAL_STATE;
    free(port->driver_data);
    port->driver_data = NULL;

    return libusb_release_interface(port->usb_dev_hdl, port->port_idx);
}

static int ftdi_port_set_config(struct usbserial_port *port, const struct usbserial_config *config)
{
    assert(port);
    assert(config);

    uint16_t config_value;
    const struct ftdi_baud_data *baud;
    int ret;

    struct ftdi_data *pdata = (struct ftdi_data*)port->driver_data;
    if (!pdata)
        return USBSERIAL_ERROR_ILLEGAL_STATE;

    baud = ftdi_serial_baud(config->baud);
    if (!baud)
        return USBSERIAL_ERROR_UNSUPPORTED_BAUD_RATE;

    config_value = config->data_bits;

    switch (config->stop_bits)
    {
    case USBSERIAL_STOPBITS_1:   config_value |= FTDI_STOP_BITS_1_CONFIG_VALUE;   break;
    case USBSERIAL_STOPBITS_1_5: config_value |= FTDI_STOP_BITS_1_5_CONFIG_VALUE; break;
    case USBSERIAL_STOPBITS_2:   config_value |= FTDI_STOP_BITS_2_CONFIG_VALUE;   break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }

    switch (config->parity)
    {
    case USBSERIAL_PARITY_NONE:  config_value |= FTDI_PARITY_NONE_CONFIG_VALUE; break;
    case USBSERIAL_PARITY_ODD:   config_value |= FTDI_PARITY_ODD_CONFIG_VALUE;  break;
    case USBSERIAL_PARITY_EVEN:  config_value |= FTDI_PARITY_EVEN_CONFIG_VALUE; break;
    case USBSERIAL_PARITY_MARK:  config_value |= FTDI_PARITY_MARK_CONFIG_VALUE; break;
    case USBSERIAL_PARITY_SPACE: config_value |= FTDI_PARITY_SPACE_CONFIG_VALUE; break;

    default: return USBSERIAL_ERROR_INVALID_PARAMETER;
    }
    
    ret = ftdi_ctrl(port, FTDI_SIO_SET_BAUD_RATE, baud->value, pdata->control_idx);
    if (ret) 
        return ret;
    return ftdi_ctrl(port, FTDI_SIO_SET_CONFIG, config_value, pdata->control_idx);
}

static int ftdi_start_reader(struct usbserial_port *port)
{
    assert(port);
    assert(port->cb_read);

    return usbserial_io_init_bulk_read_transfer(port);
}

static int ftdi_stop_reader(struct usbserial_port *port)
{
    assert(port);

    return usbserial_io_cancel_bulk_read_transfer(port);
}

static int ftdi_read_data_copy(void *dest, void *src, size_t src_size, size_t packet)
{
    size_t dest_size = 0;
    size_t pos = FTDI_MODEM_STATUS_BYTES_COUNT;
    while (pos < src_size)
    {
        memcpy(dest+dest_size, src+pos, min(packet, src_size-pos));
        dest_size += packet;
        pos += packet+FTDI_MODEM_STATUS_BYTES_COUNT;
    }
    return dest_size;
}

static int ftdi_read(struct usbserial_port *port, void *data, size_t size, int timeout)
{
    assert(port);
    
    int ret;
    size_t len, packet;
    
    struct ftdi_data *pdata = (struct ftdi_data*) port->driver_data;
    if (!pdata)
        return USBSERIAL_ERROR_ILLEGAL_STATE;

    packet = pdata->max_packet_size-FTDI_MODEM_STATUS_BYTES_COUNT;
    len = size + FTDI_MODEM_STATUS_BYTES_COUNT*(int)(size/packet);
    if (size%packet)
        len += FTDI_MODEM_STATUS_BYTES_COUNT;

    void *buffer = malloc(len);
    if (!buffer)
        return USBSERIAL_ERROR_RESOURCE_ALLOC_FAILED;

    ret = usbserial_io_bulk_read(port, buffer, len, timeout);
    if (ret >= 0)
        ret = ftdi_read_data_copy(data, buffer, ret, packet);
    
    free(buffer);
    return ret;
}

static int ftdi_write(struct usbserial_port *port, const void *data, size_t size)
{
    assert(port);

    return usbserial_io_bulk_write(port, data, size);
}

static int ftdi_purge(struct usbserial_port *port, int rx, int tx)
{
    assert(port);
    
    int rx_ret = 0, tx_ret = 0;

    struct ftdi_data *pdata = (struct ftdi_data*) port->driver_data;
    if (!pdata) 
        return USBSERIAL_ERROR_ILLEGAL_STATE;
    
    if (rx)
        rx_ret = ftdi_ctrl(port, FTDI_SIO_RESET, FTDI_SIO_RESET_PURGE_RX,
                pdata->control_idx);
    if (tx)
        tx_ret = ftdi_ctrl(port, FTDI_SIO_RESET, FTDI_SIO_RESET_PURGE_TX,
                pdata->control_idx);

    return rx_ret ? rx_ret : tx_ret;
}

static int ftdi_set_dtr_rts(struct usbserial_port *port, int dtr, int rts)
{
    int ret;

    struct ftdi_data *pdata = (struct ftdi_data*) port->driver_data;
    if (!pdata) 
        return USBSERIAL_ERROR_ILLEGAL_STATE;

    ret = ftdi_ctrl(port, FTDI_SIO_MODEM_CTRL,
            dtr?FTDI_SIO_SET_DTR_HIGH:FTDI_SIO_SET_DTR_LOW,
            pdata->control_idx);
    if (ret)
        return ret;
    
    ret = ftdi_ctrl(port, FTDI_SIO_MODEM_CTRL,
            rts?FTDI_SIO_SET_RTS_HIGH:FTDI_SIO_SET_RTS_LOW,
            pdata->control_idx);
    return ret;
}

static void ftdi_read_data_process(struct usbserial_port *port, void *data, size_t *size)
{
    assert(port);
    assert(data);
    assert(size);

    int i;
    char *buffer = (char*)data;
    struct ftdi_data* pdata = port->driver_data;
    int skip = FTDI_MODEM_STATUS_BYTES_COUNT;

    for (i = FTDI_MODEM_STATUS_BYTES_COUNT; i < (*size); ++i)
    {
        if ((i % pdata->max_packet_size) == 0)
        {
            skip += FTDI_MODEM_STATUS_BYTES_COUNT;
            ++i;
        } else
            buffer[i - skip] = buffer[i];
    }

    *size -= skip;
}

const struct usbserial_driver driver_ftdi =
{
    .check_supported_by_vid_pid = ftdi_check_supported_by_vid_pid,
    .check_supported_by_class = NULL,
    .get_device_name = ftdi_get_device_name,
    .get_ports_count = ftdi_get_ports_count,
    .port_init = ftdi_port_init,
    .port_deinit = ftdi_port_deinit,
    .port_set_config = ftdi_port_set_config,
    .start_reader = ftdi_start_reader,
    .stop_reader = ftdi_stop_reader,
    .read = ftdi_read,
    .write = ftdi_write,
    .purge = ftdi_purge,
    .set_dtr_rts = ftdi_set_dtr_rts,
    .read_data_process = ftdi_read_data_process,
};

const struct usbserial_driver *usbserial_driver_ftdi = &driver_ftdi;
