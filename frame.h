/*
 * Frame.h
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */

#ifndef FRAME_H_
#define FRAME_H_
/*
 * Здесь все что связано с формированием одного фрейма в рамках протокола
 *
 * */

#include "MyString.h"
#include  "TaskMngr.h"

typedef enum {
	SimpleWrite = 0x02,
	SimpleRead = 0x03,
	SimplePush = 0x04,
} MessageType;

// Структура десериализованного сообщения
typedef struct {
	bool_t isSecure;		 // указывает по зашифрованному или нет каналу передаются данные (0 - НЕ зашифрованный 1 - зашифрованный)
	MessageType messageType; // Тип сообщения на запись, чтение или пуш уведомления
	u08 messageID; 			 // Порядковый номер сообщения в сессии
	u08 dataSize;		 	 // размер полезной информации
	u16 deviceID;			 // идентификатор устройства
	byte_ptr data;		 	 // указатель на полезную информацию для передачи или принятую (ЗАШИФРОВАННУЮ)
}message_t;

extern const string_t OK;

/*
 * Сформирует сообщение для отправки данных во внутренний буфер
 * КОНТРОЛЬНАЯ СУММА МЛАДШИМ БАЙТОМ ВПЕРЕД!!!!!!!!!!
 * maxSize - максимальный размер выходного буфера
 * result - указатель на место куда будет записан результат
 * Возвращает размер сообщения (ноль если сформировать сообшение не удалось)
 * */
u16 formFrame(const u16 maxSize, byte_ptr result, const message_t*const msg);


/*
 * Возвращает длину полезного сообщения (ноль если распарсить не удалось)
 * sourceSize - размер исходного сообщения
 * source - указатель на исходное сообщение
 * result->id - заполняет найденным в сообщении идентификатором
 * result->dataSize - размер, больше которого не будет ничего записываться при формировании распарсенного сообщения
 * result->data - result->dataSize байт (или меньше) полученного сообщения (ЕЩЕ ЗАШИФРОВАННОЕ)
 * */
u16 parseFrame(const u16 sourceSize, const byte_ptr source, message_t* result);

#endif /* FRAME_H_ */
