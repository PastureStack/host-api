package events

import (
	"fmt"
	"sync"
	"time"

	"github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"
)

const workerTimeout = 60 * time.Second

type Handler interface {
	Handle(*docker.APIEvents) error
}

type EventRouter struct {
	handlers      map[string][]Handler
	dockerClient  *docker.Client
	listener      chan *docker.APIEvents
	workers       chan *worker
	workerTimeout time.Duration
	done          chan struct{}
	stopOnce      sync.Once
	stopErr       error
}

func NewEventRouter(bufferSize int, workerPoolSize int, dockerClient *docker.Client,
	handlers map[string][]Handler) (*EventRouter, error) {
	if bufferSize < 1 || workerPoolSize < 1 {
		return nil, fmt.Errorf("event buffer and worker pool sizes must be positive")
	}
	workers := make(chan *worker, workerPoolSize)
	for i := 0; i < workerPoolSize; i++ {
		workers <- &worker{}
	}

	eventRouter := &EventRouter{
		handlers:      handlers,
		dockerClient:  dockerClient,
		listener:      make(chan *docker.APIEvents, bufferSize),
		workers:       workers,
		workerTimeout: workerTimeout,
		done:          make(chan struct{}),
	}

	return eventRouter, nil
}

func (e *EventRouter) Start() error {
	log.Info("Starting event router.")
	if err := e.dockerClient.AddEventListener(e.listener); err != nil {
		return err
	}
	go e.routeEvents()
	return nil
}

func (e *EventRouter) Stop() error {
	if e.listener == nil {
		return nil
	}
	e.stopOnce.Do(func() {
		e.stopErr = e.dockerClient.RemoveEventListener(e.listener)
		close(e.done)
	})
	return e.stopErr
}

func (e *EventRouter) routeEvents() {
	for {
		var event *docker.APIEvents
		select {
		case <-e.done:
			return
		case received, ok := <-e.listener:
			if !ok {
				return
			}
			event = received
		}
		if event == nil {
			continue
		}

		timer := time.NewTimer(e.workerTimeout)
		var selected *worker
		for selected == nil {
			select {
			case <-e.done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case selected = <-e.workers:
			case <-timer.C:
				log.Info("Timed out waiting for event worker; continuing to wait.")
				timer.Reset(e.workerTimeout)
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		go selected.doWork(event, e)
	}
}

type worker struct{}

func (w *worker) doWork(event *docker.APIEvents, e *EventRouter) {
	defer func() {
		select {
		case e.workers <- w:
		case <-e.done:
		}
	}()
	if event == nil {
		return
	}
	if handlers, ok := e.handlers[event.Status]; ok {
		logger := log.WithFields(log.Fields{
			"action": event.Action,
			"id":     event.ID,
			"status": event.Status,
			"type":   event.Type,
		})
		logger.Debug("Processing Docker event")
		for _, handler := range handlers {
			if err := handler.Handle(event); err != nil {
				logger.WithError(err).Error("Error processing Docker event")
			}
		}
	}
}
