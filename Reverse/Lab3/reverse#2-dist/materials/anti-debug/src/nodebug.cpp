#include <iostream>
#include <Windows.h>


bool check1() {
    if (IsDebuggerPresent()) {
        std::cout << "Bad!!! Leave me alone!!!!!";
        ExitProcess(1);
    }

    return true;
}

int main()
{
    if (check1()) {
        std::cout << "You're Good! Still don't debug me plz!!";
    }
}
