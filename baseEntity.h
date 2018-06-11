/*
 * baseEntity.h
 *
 *  Created on: 26 мая 2018 г.
 *      Author: blabu
 */

#ifndef BASEENTITY_H_
#define BASEENTITY_H_

#include "TaskMngr.h"

#define KEY_SIZE 16

// Данные об устройстве
typedef struct {
	bool_t isSecure; 	// Флаг показывает работаем мы с шифрованием или без него
	u16 Id;		  		// Id устройства
	u08 Key[KEY_SIZE];  // Ключ шифрования
} Device_t;

typedef PAIR(u16, byte_ptr) ClientData_t;

// Сущность для сессии
typedef struct {
	u16 sessionId;			// Идентификатор сессии (определяет адрес, на котором работаем с клиентом)
	ClientData_t buff;	   	// Временный буфер
	Device_t* dev;			// Девайс с которым ведется сессия
	byte_ptr newKey;	 	// Новый ключ еще
	bool_t isSecureSession; // Флаг текущая секция защищенная или нет
} Client_t;

// Характеризует настройка канала
typedef struct {
	u08 address[5]; // Адресс в канале
	u08 channel;   	// Номер канала
	u08 dataLength;	// Длина буфера приема-передачи
}channel_t;

// Характеризует данные в конкретной сессии сс устройством.
// Работает на транспортном уровне
typedef struct {
		bool_t isBusy; 	// Канал занят (идет работа с каналом)
		bool_t isReady; // Канал готов (получены не обработанные данные в канале)
		u08 pipeNumber; // Номер порта (адреса) на котором работаем с клиентом (однозначно связан с номером сессии)
		channel_t pipe; // Харктеристика канала
		byte_ptr buff;	// Данные полученные на этом канале
} channelBuff_t;

extern const u08 PING_ADDR[5];

// Структура десериализованного сообщения
typedef struct {
	u08 version;		 // версия протокола указывает по зашифрованному или нет каналу передаются данные (0 - НЕ зашифрованный 1 - зашифрованный)
	bool_t isWrite; 	 // флаг указывает на запись или на чтение формруется пакет
	u16 deviceID;				 // идентификатор устройства
	u16 dataSize;		 // размер полезной информации
	byte_ptr data;		 // указатель на полезную информацию для передачи (ЗАШИФРОВАННУЮ)
}message_t;

#endif /* BASEENTITY_H_ */
