package main

import "github.com/lxn/win"

func hide(){
	win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)
}

