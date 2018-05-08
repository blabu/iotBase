/*
 * transport.h
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */

#ifndef TRANSPORTCLIENT_H_
#define TRANSPORTCLIENT_H_

#include "TaskMngr.h"

// Для работы протокола необходимо реализовать эти функции. Каждая из функций ОБЯЗАТЕЛЬНО должна вызывать execCallBack себя же.

// Функция непосредственной отправки данных
void sendTo(u16 size, byte_ptr data);

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFrom(u16 size, byte_ptr result);

// Функция сохрания параметры в память
void saveParameters(u16 id, byte_ptr key, u08 size);

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getParameters(u16* id, byte_ptr key, u08 size);

void enableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p);

void disableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p);

#endif /* TRANSPORTCLIENT_H_ */
