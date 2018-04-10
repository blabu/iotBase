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
 * bufSize - размер полезной информации
 * buf - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * Возвращает результирующий ПОЛНЫЙ размер сообщения
 * КОНТРОЛЬНАЯ СУММА МЛАДШИМ БАЙТОМ ВПЕРЕД!!!!!!!!!!
 * */
u16 formFrame(const u16 maxSize, byte_ptr result, u16 command, const u16 dataSize, const byte_ptr data, bool_t isWrite);

/*
 * Возвращает распарсенный идентификатор и полезное сообщение (ЕЩЕ ЗАШИФРОВАННОЕ)
 * */
u16 parseFrame(u16*const parseId, const u16 sourceSize, const byte_ptr source, const u16 sz, byte_ptr result);


#endif /* FRAME_H_ */
