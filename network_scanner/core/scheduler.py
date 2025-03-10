"""
Scheduler - Task scheduling and management.

This module provides functionality for scheduling tasks to run at
specified intervals or at specific times.
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

class Task:
    """Represents a scheduled task."""
    
    def __init__(
        self,
        func: Callable,
        interval: Optional[int] = None,
        run_at: Optional[Union[datetime, List[datetime]]] = None,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        run_once: bool = False
    ):
        """
        Initialize a scheduled task.
        
        Args:
            func: Function to call when task is executed
            interval: Interval in seconds between task executions
            run_at: Specific datetime(s) to run the task
            args: Positional arguments to pass to the function
            kwargs: Keyword arguments to pass to the function
            name: Name for the task
            run_once: Whether to run the task only once
        """
        self.func = func
        self.interval = interval
        self.run_at = run_at if isinstance(run_at, list) else ([run_at] if run_at else None)
        self.args = args or []
        self.kwargs = kwargs or {}
        self.name = name or func.__name__
        self.run_once = run_once
        self.last_run = None
        self.next_run = None
        self.running = False
        self.completed = False
        self._calculate_next_run()
        
        self._id = id(self)
        
    def _calculate_next_run(self) -> None:
        """Calculate the next run time based on interval or run_at."""
        now = datetime.now()
        
        if self.completed:
            self.next_run = None
            return
            
        if self.interval:
            if self.last_run:
                self.next_run = self.last_run + timedelta(seconds=self.interval)
            else:
                self.next_run = now
        elif self.run_at:
            future_times = [t for t in self.run_at if t > now]
            self.next_run = min(future_times) if future_times else None
        else:
            self.next_run = now
            
    def is_due(self) -> bool:
        """
        Check if the task is due to run.
        
        Returns:
            True if the task is due, False otherwise
        """
        if self.completed or not self.next_run:
            return False
            
        return datetime.now() >= self.next_run
        
    def execute(self) -> Any:
        """
        Execute the task and update its state.
        
        Returns:
            The result of the function call
        """
        if self.completed:
            return None
            
        self.running = True
        self.last_run = datetime.now()
        
        try:
            logger.debug(f"Executing task: {self.name}")
            result = self.func(*self.args, **self.kwargs)
            
            if self.run_once:
                self.completed = True
                
            self._calculate_next_run()
            return result
            
        except Exception as e:
            logger.error(f"Error executing task {self.name}: {e}")
            
        finally:
            self.running = False


class Scheduler:
    """Scheduler for managing and executing tasks."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one scheduler exists."""
        if cls._instance is None:
            cls._instance = super(Scheduler, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the scheduler if not already initialized."""
        if self._initialized:
            return
            
        self._tasks = {}
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._initialized = True
        logger.debug("Scheduler initialized")
    
    def add_task(self, task: Task) -> int:
        """
        Add a task to the scheduler.
        
        Args:
            task: Task to add
            
        Returns:
            Task ID
        """
        task_id = task._id
        self._tasks[task_id] = task
        logger.debug(f"Added task {task.name} with ID {task_id}")
        return task_id
        
    def schedule(
        self,
        func: Callable,
        interval: Optional[int] = None,
        run_at: Optional[Union[datetime, List[datetime]]] = None,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        run_once: bool = False
    ) -> int:
        """
        Schedule a task to run.
        
        Args:
            func: Function to call when task is executed
            interval: Interval in seconds between task executions
            run_at: Specific datetime(s) to run the task
            args: Positional arguments to pass to the function
            kwargs: Keyword arguments to pass to the function
            name: Name for the task
            run_once: Whether to run the task only once
            
        Returns:
            Task ID
        """
        task = Task(func, interval, run_at, args, kwargs, name, run_once)
        return self.add_task(task)
        
    def remove_task(self, task_id: int) -> bool:
        """
        Remove a task from the scheduler.
        
        Args:
            task_id: ID of the task to remove
            
        Returns:
            True if removed, False otherwise
        """
        if task_id in self._tasks:
            task = self._tasks.pop(task_id)
            logger.debug(f"Removed task {task.name} with ID {task_id}")
            return True
        return False
        
    def get_task(self, task_id: int) -> Optional[Task]:
        """
        Get a task by ID.
        
        Args:
            task_id: ID of the task to get
            
        Returns:
            Task if found, None otherwise
        """
        return self._tasks.get(task_id)
        
    def get_all_tasks(self) -> Dict[int, Task]:
        """
        Get all tasks.
        
        Returns:
            Dictionary of task ID to task
        """
        return self._tasks.copy()
        
    def start(self) -> None:
        """
        Start the scheduler in a background thread.
        """
        if self._running:
            logger.warning("Scheduler already running")
            return
            
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Scheduler started")
        
    def stop(self) -> None:
        """
        Stop the scheduler.
        """
        if not self._running:
            logger.warning("Scheduler not running")
            return
            
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        logger.info("Scheduler stopped")
        
    def _run_loop(self) -> None:
        """
        Main scheduler loop that checks and executes due tasks.
        """
        logger.debug("Scheduler loop started")
        
        while self._running and not self._stop_event.is_set():
            try:
                # Find and execute due tasks
                for task_id, task in list(self._tasks.items()):
                    if task.is_due() and not task.running:
                        task.execute()
                        
                        # Remove completed one-time tasks
                        if task.completed:
                            self._tasks.pop(task_id, None)
                
                # Sleep for a short time to avoid CPU spinning
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                
        logger.debug("Scheduler loop ended")
        
    def is_running(self) -> bool:
        """
        Check if the scheduler is running.
        
        Returns:
            True if running, False otherwise
        """
        return self._running


class AsyncScheduler:
    """Asynchronous scheduler for managing and executing async tasks."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one async scheduler exists."""
        if cls._instance is None:
            cls._instance = super(AsyncScheduler, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the async scheduler if not already initialized."""
        if self._initialized:
            return
            
        self._tasks = {}
        self._running = False
        self._task = None
        self._initialized = True
        logger.debug("AsyncScheduler initialized")
    
    def add_task(self, task: Task) -> int:
        """
        Add a task to the scheduler.
        
        Args:
            task: Task to add
            
        Returns:
            Task ID
        """
        task_id = task._id
        self._tasks[task_id] = task
        logger.debug(f"Added async task {task.name} with ID {task_id}")
        return task_id
        
    def schedule(
        self,
        func: Callable,
        interval: Optional[int] = None,
        run_at: Optional[Union[datetime, List[datetime]]] = None,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        run_once: bool = False
    ) -> int:
        """
        Schedule an async task to run.
        
        Args:
            func: Async function to call when task is executed
            interval: Interval in seconds between task executions
            run_at: Specific datetime(s) to run the task
            args: Positional arguments to pass to the function
            kwargs: Keyword arguments to pass to the function
            name: Name for the task
            run_once: Whether to run the task only once
            
        Returns:
            Task ID
        """
        task = Task(func, interval, run_at, args, kwargs, name, run_once)
        return self.add_task(task)
        
    def remove_task(self, task_id: int) -> bool:
        """
        Remove a task from the scheduler.
        
        Args:
            task_id: ID of the task to remove
            
        Returns:
            True if removed, False otherwise
        """
        if task_id in self._tasks:
            task = self._tasks.pop(task_id)
            logger.debug(f"Removed async task {task.name} with ID {task_id}")
            return True
        return False
        
    async def start(self) -> None:
        """
        Start the async scheduler.
        """
        if self._running:
            logger.warning("AsyncScheduler already running")
            return
            
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("AsyncScheduler started")
        
    async def stop(self) -> None:
        """
        Stop the async scheduler.
        """
        if not self._running:
            logger.warning("AsyncScheduler not running")
            return
            
        self._running = False
        if self._task:
            await asyncio.wait_for(self._task, timeout=1.0)
        logger.info("AsyncScheduler stopped")
        
    async def _run_loop(self) -> None:
        """
        Main async scheduler loop that checks and executes due tasks.
        """
        logger.debug("AsyncScheduler loop started")
        
        while self._running:
            try:
                # Find and execute due tasks
                for task_id, task in list(self._tasks.items()):
                    if task.is_due() and not task.running:
                        # Execute async function
                        if asyncio.iscoroutinefunction(task.func):
                            await task.func(*task.args, **task.kwargs)
                        else:
                            task.func(*task.args, **task.kwargs)
                            
                        task.running = False
                        task.last_run = datetime.now()
                        
                        if task.run_once:
                            task.completed = True
                            self._tasks.pop(task_id, None)
                        else:
                            task._calculate_next_run()
                
                # Sleep for a short time to avoid CPU spinning
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in async scheduler loop: {e}")
                
        logger.debug("AsyncScheduler loop ended")
        
    def is_running(self) -> bool:
        """
        Check if the async scheduler is running.
        
        Returns:
            True if running, False otherwise
        """
        return self._running


# Create the singleton instances
scheduler = Scheduler()
async_scheduler = AsyncScheduler() 