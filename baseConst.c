/*
 * baseEntity.c
 *
 *  Created on: 26 мая 2018 г.
 *      Author: blabu
 */
#include "baseEntity.h"


const u08 PING_ADDR[5] = {0xCA, 0xFE, 0xBA, 0xBE, 0xAD}; // Адрес пинга сервера (у всех серверов одинаковый)
																// по этому адресу сервер вернет свой идентификатор
																// (если ему разрешены регистрации)
																// + на этом адресе он может работать как обычный узел
