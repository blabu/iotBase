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

extern const string_t header;
extern const string_t WriteToServerSymb;
extern const string_t ReadFromSeverSymb;
extern const string_t OK;

/*
 * Сформирует сообщение для отправки данных во внутренний буфер
 * КОНТРОЛЬНАЯ СУММА МЛАДШИМ БАЙТОМ ВПЕРЕД!!!!!!!!!!
 * maxSize - максимальный размер выходного буфера
 * result - указатель на место куда будет записан результат
 * command - В рамках текущего протокола идентификатор устройства
 * dataSize - размер полезной информации
 * data - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * isWrite - флаг указывает на запись или на чтение формруется пакет
 * isSecure - флаг указывает по зашифрованному или нет каналу передаются данные
 * Возвращает размер сообщения (ноль если сформировать сообшение не удалось)
 * */
u16 formFrame(const u16 maxSize, byte_ptr result, u16 command,
		      const u16 dataSize, const byte_ptr data, bool_t isWrite, bool_t isSecure);

/*
 * Возвращает длину полезного сообщения (ноль если распарсить не удалось)
 * parseId - заполняет найденным в сообщении идентификатором
 * sourceSize - размер исходного сообщения
 * source - указатель на исходное сообщение
 * sz - размер, больше которого не будет ничего записываться при формировании распарсенного сообщения
 * result - sz байт (или меньше) полученного сообщения (ЕЩЕ ЗАШИФРОВАННОЕ)
 * IsSecure - указатель куда будет записано канал передачи сообщения зашифрован или нет
 * */
u16 parseFrame(u16*const parseId, const u16 sourceSize, const byte_ptr source,
		       const u16 sz, byte_ptr result, bool_t* isSecure);

#endif /* FRAME_H_ */
