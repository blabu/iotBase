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

/*
 * Сформирует сообщение для отправки данных во внутренний буфер
 * bufSize - размер полезной информации
 * buf - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * Возвращает результирующий ПОЛНЫЙ размер сообщения
 * */
u16 formFrame(u16 maxSize, byte_ptr result, u16 command, u16 bufSize, byte_ptr buf);

/*
 * Возвращает распарсенный идентификатор и полезное сообщение (ЕЩЕ ЗАШИФРОВАННОЕ)
 * */
u16 parseFrame(u16 sourceSize, byte_ptr source, u16 sz, byte_ptr result);


#endif /* FRAME_H_ */
