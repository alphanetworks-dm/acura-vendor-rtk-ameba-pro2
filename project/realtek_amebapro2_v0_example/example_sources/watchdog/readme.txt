Example Description

This example describes how to use the WatchDog API.

Requirement Components: 
    NONE

In this example, WatchDog is set up to 5s timeout.
The WatchDog will not bark if refresh it before timeout. The timer is also reloaded after refresh. Otherwise, it will reboot the system in default or call callback function if registered.

Define RUN_CALLBACK_IF_WATCHDOG_BARKS 1 for WatchDog interrupt mode, define 0 for reset mode.

