#ifndef KILLER_H
#define KILLER_H

template<typename F>
class Killer {
public:
    Killer(F _kf): killFunc(_kf) {};

    ~Killer() {
        killFunc();     // Nobody will go alive
    }
private:
    F killFunc;
};


#endif // KILLER_H
