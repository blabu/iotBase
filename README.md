Простая библиотека для передачи и получения данных клиентом с сервера. 
Для безопастности используется блочный алгоритм шифрования AES128
Для работы библиотеки необходимо реализовать функции транспортного уровня 
(которые непосредственно передают данные в физическом мире).
И функции сохранения и считывания регистрационных данных из памяти устройств.
Сигнатуры всех необходимых для реализации функций находятся в файле transport.h

