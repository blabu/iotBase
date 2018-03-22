/*
 * ApplicationLayer.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */


#include "IotProtocolClient.h"
#include "MyString.h"

/*!!!Команды!!!*/
static const string_t registerAttribute = "?;REG";
/* .
 * .
 * .
 * */

/* Регистрация устройства по его типу в системе. Выполняется без шифрования
 * Заполнит поле CryptKey ключом шифрования используется AES128
 */
void Register(BaseSize_t type, BaseParam_t arg_p){
	if(type == 0) {
		execCallBack(Register);
		return;
	}
	EnableSecurity(FALSE); // Регистрация выполняется без шифрования
	SetId(type);
	changeCallBackLabel(Register,WriteClient);
	SetTask(WriteClient,strSize(registerAttribute),(BaseParam_t)registerAttribute);
}
