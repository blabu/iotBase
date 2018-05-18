/*
 * IotProtocol.h
 *
 *  Created on: 11 мар. 2018 г.
 *      Author: blabu
 */

/*
 * Result message has a form $V1xxxxYYYY=AAA...AAAcc
 * where '$' - start symbol
 * V1 - version of protocol (0 - F posible variant)
 * xxxx - MESSAGE_SIZE message size ascii format (max 'FFFF')
 * YYYY - unique device identificator
 *  '=' - delim symbol between identifier and arguments
 *  AAA...AAA - arguments of function (may be binary) and can be crypted
 *  cc - CRC16 binary не зашифрованный МЛАДШИМ БАЙТОМ ВПЕРЕД
 *  Для шифрования используется симметричный алгоритм AES128 (с ключом в 16 байт)
 *  С каждой сессией передачи ключ меняется
 *  Заголовок пакета должен быть в формате ASCII строк для обеспечения совместивмости с предыдущими версиями
 *
 */

#ifndef IOTPROTOCOLCLIENT_H_
#define IOTPROTOCOLCLIENT_H_

#include <initLowLevelModule.h>
#include "TaskMngr.h"

#define PROTOCOL_BUFFER_SIZE 32 // Размер буферов приема и передачи

/*
 * Инициализация системы если Id не нулевой
 * */
void InitializeClient();
u16 getDeviceId();
void setId(u16 id);
void setSecurity(bool_t enable);
void setKey(u16 sz, byte_ptr key);

/* Отправка данных зашифрованным каналом
 * message - указатель на данные которые необходимо отправить
 * size - их размер
 * После выполнения этой функции key будет обновлен.
 * */
void WriteClient(u16 size, byte_ptr message);


/*Читает данные и заполняет поле result принятыми данными, но не более размера size
 * При этом ключ шифрования не меняется
 * */
void ReadClient(u16 size, byte_ptr result);

typedef enum {
	STATUS_OK = 0,
	STATUS_NO_SEND,
	STATUS_NO_RECEIVE,
	DEVICEID_IS_NULL,
	MEMMORY_ALOC_ERR,
	STATUS_BAD_KEY
} ProtocolStatus_t;
/* Возвращает статус последней выполненой команды
 * */
ProtocolStatus_t GetLastStatus();

#endif /* IOTPROTOCOLCLIENT_H_ */
