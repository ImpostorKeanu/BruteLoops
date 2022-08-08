BruteLoops is a protocol agnostic password guessing API capable
of executing highly configurable and performant attacks against
authentication interfaces. Supporting logic also facilitates
timing capabilities that can be used to adapt guessing behavior
to match lockout policies commonly seen in web applications and
Active Directory environments.

Unlike most applications, BruteLoops reads inputs from a
SQLite database. While this does impact performance with attacks
invloving large datasets, it facilitates the granular timing
configurations needed to mitigate lockout events and/or evade
detection while attacking network services.
