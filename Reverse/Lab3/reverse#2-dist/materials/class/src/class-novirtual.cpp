#include <stdio.h>


class Entity {
	int age;
public:
    Entity() {
        this->age = 0;
    }
    void Speak() {
        printf("An Entity can speak!\n");
    }
};

class Cat {
	int age;
public:
    Cat() {
        this->age = 0;
    }
    void Speak() {
        printf("An Cat can speak!\n");
    }
};

int main() {
    Entity entity = Entity();
    entity.Speak();

    Cat cat = Cat();
    cat.Speak();
}

// g++ class-novirtual.cpp -o class-novirtual