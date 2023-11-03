#include <stdio.h>


class Entity {
	int age;
public:
    Entity() {
        this->age = 0;
    }
    virtual void Speak() {
        printf("An Entity can speak!\n");
    }
};

class Cat: public Entity {
	int age;
public:
    Cat() {
        this->age = 0;
    }
    virtual void Speak() {
        printf("An Cat can speak!\n");
    }
};

int main() {
    Entity entity = Entity();
    entity.Speak();

    Cat cat = Cat();
    dynamic_cast<Entity*>(&cat)->Speak();
}


// g++ class-virtual.cpp -o class-virtual
