package config

import (
	"github.com/fsnotify/fsnotify"
	"log"
)

func WatchConfig(callback func()) {
	log.Println("watching config...")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(cf)
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			//just for vim editor
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				log.Println("event: ", event.Op)
				err := watcher.Add(cf)
				if err != nil {
					log.Fatal(err)
				}
				callback()
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)

		}
	}
}
