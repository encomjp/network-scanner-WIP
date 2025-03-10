"""
Event Bus - Central message broker for inter-module communication.

This module implements a publish/subscribe pattern to allow modules to
communicate with each other without direct dependencies.
"""

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

class EventBus:
    """Central event bus for pub/sub messaging between modules."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one event bus exists."""
        if cls._instance is None:
            cls._instance = super(EventBus, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the event bus if not already initialized."""
        if self._initialized:
            return
            
        self._subscribers = defaultdict(set)
        self._event_history = []
        self._max_history = 1000
        self._history_enabled = True
        self._initialized = True
        logger.debug("EventBus initialized")
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """
        Subscribe to an event type with a callback function.
        
        Args:
            event_type: The type of event to subscribe to
            callback: Function to call when event is published
        """
        self._subscribers[event_type].add(callback)
        logger.debug(f"Subscribed to event type: {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """
        Unsubscribe from an event type.
        
        Args:
            event_type: The type of event to unsubscribe from
            callback: Function to remove from subscribers
        """
        if event_type in self._subscribers and callback in self._subscribers[event_type]:
            self._subscribers[event_type].remove(callback)
            logger.debug(f"Unsubscribed from event type: {event_type}")
    
    def publish(self, event_type: str, data: Any = None) -> None:
        """
        Publish an event to all subscribers.
        
        Args:
            event_type: The type of event to publish
            data: Data associated with the event
        """
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        if self._history_enabled:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)
        
        logger.debug(f"Publishing event: {event_type}")
        
        for callback in self._subscribers.get(event_type, set()):
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")
    
    async def publish_async(self, event_type: str, data: Any = None) -> None:
        """
        Publish an event asynchronously.
        
        Args:
            event_type: The type of event to publish
            data: Data associated with the event
        """
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        if self._history_enabled:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)
        
        logger.debug(f"Publishing async event: {event_type}")
        
        for callback in self._subscribers.get(event_type, set()):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in async event callback: {e}")
    
    def get_event_history(self, event_type: Optional[str] = None) -> List[Dict]:
        """
        Get event history, optionally filtered by event type.
        
        Args:
            event_type: Optional filter for event type
            
        Returns:
            List of event dictionaries
        """
        if event_type:
            return [e for e in self._event_history if e["type"] == event_type]
        return self._event_history.copy()
    
    def clear_event_history(self) -> None:
        """Clear the event history."""
        self._event_history = []
        
    def set_history_enabled(self, enabled: bool) -> None:
        """Enable or disable event history recording."""
        self._history_enabled = enabled
        
    def set_max_history(self, max_history: int) -> None:
        """Set the maximum number of events to keep in history."""
        self._max_history = max_history
        if len(self._event_history) > max_history:
            self._event_history = self._event_history[-max_history:]


# Create the singleton instance
event_bus = EventBus() 