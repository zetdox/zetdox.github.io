# RE // SolaraBootstrapper.exe
---

* Главный исполняемый файл: **BootstrapperNew.exe**
* Размер файла: **8,26 мб (8467 кб)**
* SHA256: **bbc1e249b5d1212db61e5fee3a63ce614388827bd429cf06dba7699f586abf27**
* MD5: **aa7a86cceb8f870b1ada478c05df80f5**
* Упаковщик: **Custom**
* Компилятор: **RustC (Rust)**
* Энтропия: **7.26~ (резкий спад до 2.1)**
* Тип: **Dropper**

* Дроп-файл: **6610761ea14b.exe** **(csrss.exe)**
* Размер файла: **1.03 мб (1057 кб)**
* SHA256: **007c9981ae0981dc54d4d05715ff1371bd0baf9ebf5ec22da4e12a12a408dff0**
* MD5: **8c62c25ec20e5092d7a1ce349b03ea17**
* Язык: **C# (.NET)**
* Энтропия: **7.2~**
* Тип: **Stealer**

#### Инструменты которые использовались в ходе анализа:
---
* Статический анализ: **IDA Pro, dnSpy, HxD**
* Динамический анализ: **dnSpy, ProcessHacker, FakeNet**

#### Структура проекта:
---
* Папки: **autoexec, Solara, workspace**
* Исполняемые файлы: **SolaraBootstrapper.exe, SLaunch.exe, Solara.exe**

#### Техническая часть:
---
Данный файл был скачан из открытого источника YouTube, по запросу "cheats roblox"

Основной исполняемый файл создает дроп-файл по каталогу: **C:\Users\User\AppData\Local\Temp**

Дроп-файл маскируется под системный файл: **csrss.exe** (*Client/Server Runtime Subsystem*)

Сначала был вскрыт **SolaraBootstrapper.exe**, из интересного можно выделить:

```x86asm
.rdata:0000000140022568 unk_140022568 db 7 ; DATA XREF: sub_140001000+64B↑o .rdata:0000000140022569 db 5Bh ; [ 
.rdata:000000014002256A db 4Ch ; L 
.rdata:000000014002256B db 4Fh ; O 
.rdata:000000014002256C db 47h ; G 
.rdata:000000014002256D db 5Dh ; ] 
.rdata:000000014002256E db 20h 
.rdata:000000014002256F db 5Bh ; [
.rdata:0000000140022570 db 0C0h .rdata:0000000140022571 db 2 
.rdata:0000000140022572 db 5Dh ; ]"
```

Файл создает лог-файл типа:
```log-file
[LOG] [NUM?] содержимое
```

Соответственно, данный лог-файл был быстро найден в каталоге  **C:\ProgramData** при запуске основного исполняемого файла. 

* Имя файла: **svc_8f123950.log**
* Содержимое: 
```log-file
[LOG] [1782625697] state.junk
[LOG] [1782625697] state.payload
[LOG] [1782625697] state.payload.decrypted
[LOG] [1782625697] state.load.start
[LOG] [1782625697] state.load.done
[LOG] [1782625697] state.exec.start
```
Таким образом можно сказать что, программа создает лог-файл для хранения состояния шифрования файла.

*Число в квадратных скобках (`[1782625697]`) предположительно является временной меткой (Unix timestamp) или идентификатором сессии, используемым для отслеживания состояния выполнения программы.*

Так же в программе была зафиксирована работа с JSON:
```x86asm
mov rcx, [rbx]
mov r9, [rbx+8] 
lea rax, asc_14018DDA8 ; " {\n"
mov r14, r8 
mov r8d, 3 
mov r15, rdx 
mov rdx, rax 
call qword ptr [r9+18h] 
mov rdx, r15 
mov r8, r14 
mov r14b, 1 
test al, al 
jnz loc_140004F01 
mov r12, rdx 
mov r15, r8 
movzx r8d, al 
xor r8, 3
lea rcx, asc_14018EB1E ; ", " 
lea rdx, asc_14018EDEE ; " { "
test al, al 
cmovnz rdx, rcx
mov rcx, [rbx]
mov rax, [rbx+8]
call qword ptr [rax+18h]
test al, al
jnz short loc_140004F01
```

Помимо этого, при запуске дроп-файла dnSpy показал, что программа обращается к System.Management.dll, это означает, что программа запрашивает у библиотеки модель процессора, видеокарты. Возможно, программа собирает данные чтобы определить, запускается ли программа на виртуальной машине или нет.

```dnSpy
(CLR v4.0.30319: 6610761ea14b.exe): Загружено 'C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Management\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Management.dll'.
```

Так же библиотека программы **System.Web.Extensions.dll** содержит класс **JavaScriptSerializer**, что доказывает факт использования JSON. **JavaScriptSerializer** класс который берет объект из памяти и вставляет его в JSON-формат:

```json
{
  "computer": "DESKTOP-PC",
  "cpu": "Intel"
}
```

Возможно после этого файл идет на C2-сервер злоумышленника.

Так же, программа имеет широкий спектр проверок, на стадии запуска программа проверяет не запущена ли она на виртуальной машине (**Hyper-V, qemu**), проверяет устройство на такие программы как: **IDA Pro, x64dbg, x32dbg, Wireshark, HxD, ProcessHacker**. Также идентифицированы имена пользователей и компьютеров (**WALKER, John, Abby, Bruno, George**), используемые для проверки на наличие защитных песочниц.

```hex
M�o�d�e�l�� x�3�2�d�b�g�� x�6�4�d�b�g�� w�i�n�d�b�g��o�l�l�y�d�b�g��d�n�s�p�y��#i�m�m�u�n�i�t�y� �d�e�b�u�g�g�e�r��h�y�p�e�r�d�b�g��i�d�a��i�d�a�6�4��c�h�e�a�t�e�n�g�i�n�e��c�h�e�a�t� �e�n�g�i�n�e��p�r�o�c�m�o�n��w�i�r�e�s�h�a�r�k��f�i�d�d�l�e�r��p�r�o�c�e�s�s�h�a�c�k�e�r��h�x�d��c�h�a�r�l�e�s�� b�u�r�p��b�u�r�p�s�u�i�t�e��p�o�s�t�m�a�n��t�e�l�e�r�i�k� �f�i�d�d�l�e�r��m�i�t�m�p�r�o�x�y��z�a�p��o�w�a�s�p� �z�a�p��p�r�o�x�y�m�a�n��h�t�t�p�d�e�b�u�g�g�e�r�� W�A�L�K�E�R��W�A�L�K�E�R�-�P�C�� J�o�h�n��J�O�H�N�-�P�C�� A�b�b�y��B�r�u�n�o�� g�e�o�r�g�e"
```

При запуске программа проверяет и регион пользователя через запросы к `http://ip-api.com` в формате JSON, возможно чтобы потом передать информацию на C2-сервер.

```hex
soft.CSharp�T�����r�u��/h�t�t�p�:�/�/�i�p�-�a�p�i�.�c�o�m�/�j�s�o�n�/��G�E�T��!a�p�p�l�i�c�a�t�i�o�n�/�j�s�o�n��c�o�u�n�t�r�y��c�o�u�n�t�r�y"
```

#### C2-сервера:
---
*Учитывая наличие JSON-формата через `JavaScriptSerializer` и работу с `System.Web.Extensions.dll`, можно предположить, что программа отправляет данные на удаленный сервер через HTTP/HTTPS POST-запросы с JSON-телом. Однако из-за сильной обфускации точный URL C2-сервера на момент анализа не был найден.*

## Итог:
---
Данный файл был классифицирован как дроппер. Имеет связку Rust + .NET (C#), в основном ворует данные и имеет сложную и продуманную защиту.
