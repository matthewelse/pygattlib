// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <exception>

#include "gattlib.h"
#include "gattservices.h"

#include <boost/algorithm/string.hpp>

DiscoveryService::DiscoveryService(const std::string device) :
	_device(device),
	_device_desc(-1) {

	int dev_id = hci_devid(device.c_str());
	if (dev_id < 0)
		throw std::runtime_error("Invalid device!");

	_device_desc = hci_open_dev(dev_id);
	if (_device_desc < 0)
		throw std::runtime_error("Could not open device!");
	}

DiscoveryService::~DiscoveryService() {
	if (_device_desc != -1)
		hci_close_dev(_device_desc);
}

void
DiscoveryService::enable_scan_mode() {
	int result;
	uint8_t scan_type = 0x01;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t own_type = 0x00;
	uint8_t filter_policy = 0x00;

	result = hci_le_set_scan_parameters
		(_device_desc, scan_type, interval, window,
		 own_type, filter_policy, 10000);

	if (result < 0)
		throw std::runtime_error
			("Set scan parameters failed (are you root?)");

	result = hci_le_set_scan_enable(_device_desc, 0x01, 1, 10000);
	if (result < 0)
		throw std::runtime_error("Enable scan failed");
}

void
DiscoveryService::get_advertisements(int timeout, boost::python::dict & ret) {
	struct hci_filter old_options;
	socklen_t slen = sizeof(old_options);
	if (getsockopt(_device_desc, SOL_HCI, HCI_FILTER,
				   &old_options, &slen) < 0)
		throw std::runtime_error("Could not get socket options");

	struct hci_filter new_options;
	hci_filter_clear(&new_options);
	hci_filter_set_ptype(HCI_EVENT_PKT, &new_options);
	hci_filter_set_event(EVT_LE_META_EVENT, &new_options);

	if (setsockopt(_device_desc, SOL_HCI, HCI_FILTER,
				   &new_options, sizeof(new_options)) < 0)
		throw std::runtime_error("Could not set socket options\n");

	int len;
	unsigned char buffer[HCI_MAX_EVENT_SIZE];
	struct timeval wait;
	fd_set read_set;
	wait.tv_sec = timeout;
	int ts = time(NULL);

	while(1) {
		FD_ZERO(&read_set);
		FD_SET(_device_desc, &read_set);

		int err = select(FD_SETSIZE, &read_set, NULL, NULL, &wait);
		if (err <= 0)
			break;

		len = read(_device_desc, buffer, sizeof(buffer));
        process_input(buffer, len, ret);

		int elapsed = time(NULL) - ts;
		if (elapsed >= timeout)
			break;

		wait.tv_sec = timeout - elapsed;
	}

	setsockopt(_device_desc, SOL_HCI, HCI_FILTER,
			   &old_options, sizeof(old_options));
}

void
DiscoveryService::process_input(unsigned char* buffer, int size, boost::python::dict & ret) {

    for (int i=0; i < size; i++) {
        unsigned char* ptr = buffer + HCI_EVENT_HDR_SIZE + 1;
        evt_le_meta_event* meta = (evt_le_meta_event*) ptr;

        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) {
        //|| (uint8_t)buffer[BLE_EVENT_TYPE] != BLE_SCAN_RESPONSE) {
            //std::cout << "not an advertising report" << std::endl;
            continue;
        }

        le_advertising_info* info;
        info = (le_advertising_info*) (meta->data + 1);

        char addr[18];
        ba2str(&info->bdaddr, addr);

        int flags = parse_flags(info->data, info->length);
        int appearance = parse_appearance(info->data, info->length);
        std::string name = parse_name(info->data, info->length);
        boost::python::list uuids = parse_uuids(info->data, info->length);

        if (!ret.contains(addr)) {
        	boost::python::dict new_object;
        	ret[addr] = new_object;
    	}

    	if (!ret[addr].contains("flags") || flags != 0)
    		ret[addr]["flags"] = flags;

    	if (!ret[addr].contains("appearance") || appearance != 0)
    		ret[addr]["appearance"] = appearance;

    	// it's safe to cast the length to an unsigned int, since length > 0.
    	if (!ret[addr].contains("name") || name.length() > (unsigned int)boost::python::len(ret[addr]["name"]))
    		ret[addr]["name"] = name;

    	if (!ret[addr].contains("uuids") || boost::python::len(uuids) > boost::python::len(ret[addr]["uuids"]))
    		ret[addr]["uuids"] = uuids;

        ptr += sizeof(evt_le_meta_event);
    }
}

int
DiscoveryService::parse_appearance(uint8_t* data, size_t size) {
	size_t offset = 0;

	while (offset < size) {
		uint8_t field_len = data[0];

		if (field_len == 0 || offset + field_len > size) {
			// this probably ought to be an exception
			return 0;
		}

		if (data[1] == EIR_APPEARANCE) {
			uint16_t appearance = ((uint16_t *)(data + 2))[0];
			return appearance;
		}

		offset += field_len + 1;
		data += field_len + 1;
	}

	return 0;
}

boost::python::list
DiscoveryService::parse_uuids(uint8_t * data, size_t size) {
	size_t offset = 0;
	boost::python::list uuids;

	while (offset < size) {
		uint8_t field_len = data[0];

		if (field_len == 0 || offset + field_len > size) {
			// this probably ought to be an exception
			return uuids;
		}

		if (data[1] == EIR_16BIT_UUIDS_COMPLETE || data[1] == EIR_16BIT_UUIDS_INCOMPLETE) {
			int number_of_uuids = (field_len - 1) / 2;
			uint16_t *big_uuids = (uint16_t *)(data + 2);

			for (int i = 0; i < number_of_uuids; i++) {
				// add this uuid to the list
				uuids.append(big_uuids[i]);
			}
		} else if (data[1] == EIR_32BIT_UUIDS_COMPLETE || data[1] == EIR_32BIT_UUIDS_INCOMPLETE) {
			int number_of_uuids = (field_len - 1) / 4;
			uint32_t *big_uuids = (uint32_t *)(data + 2);

			for (int i = 0; i < number_of_uuids; i++) {
				// add this uuid to the list
				uuids.append(big_uuids[i]);
			}
		} else if (data[1] == EIR_128BIT_UUIDS_COMPLETE || data[1] == EIR_128BIT_UUIDS_INCOMPLETE) {
			int number_of_uuids = (field_len - 1) / 16;
			uint32_t *big_uuids = (uint32_t *)(data + 2);

			for (int i = 0; i < number_of_uuids * 4; i+=4) {
				// add this uuid to the list
				uuids.append(boost::python::make_tuple(big_uuids[i], big_uuids[i+1], big_uuids[i+2], big_uuids[i+3]));
			}
		}

		offset += field_len + 1;
		data += field_len + 1;
	}

	return uuids;
}

int
DiscoveryService::parse_flags(uint8_t* data, size_t size) {
	size_t offset = 0;

	while (offset < size) {
		uint8_t field_len = data[0];

		if (field_len == 0 || offset + field_len > size) {
			// this probably ought to be an exception
			return 0;
		}

		if (data[1] == EIR_FLAGS)
			return data[2];

		offset += field_len + 1;
		data += field_len + 1;
	}

	return 0;
}

std::string
DiscoveryService::parse_name(uint8_t* data, size_t size) {
	size_t offset = 0;
	std::string unknown = "";

	while (offset < size) {
		uint8_t field_len = data[0];
		size_t name_len;

		if (field_len == 0 || offset + field_len > size)
			return unknown;

		switch (data[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;

			// remove any trailing \x00s
			if (data[1 + name_len] == '\0')
				name_len--;

			if (name_len > size)
				return unknown;

			return std::string((const char*)(data + 2), name_len);
		}

		offset += field_len + 1;
		data += field_len + 1;
	}

	return unknown;
}

void
DiscoveryService::disable_scan_mode() {
	if (_device_desc == -1)
		throw std::runtime_error("Could not disable scan, not enabled yet");

	int result = hci_le_set_scan_enable(_device_desc, 0x00, 1, 10000);
	if (result < 0)
		throw std::runtime_error("Disable scan failed");
}

boost::python::dict
DiscoveryService::discover(int timeout) {
	boost::python::dict retval;
	enable_scan_mode();
	get_advertisements(timeout, retval);
	disable_scan_mode();

	return retval;
}
