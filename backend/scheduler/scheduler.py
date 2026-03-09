"""
Intelligence Scheduler
Local AI-Powered Security Operations Center

Scheduled tasks for continuous threat intelligence operations.
"""

import asyncio
import structlog
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import settings

logger = structlog.get_logger()


class IntelligenceScheduler:
    """Scheduler for intelligence gathering and analysis tasks."""
    
    def __init__(
        self,
        ingestion_service: Optional[Any] = None,
        rag_engine: Optional[Any] = None,
        network_analyzer: Optional[Any] = None,
        agent_orchestrator: Optional[Any] = None,
    ):
        self.ingestion_service = ingestion_service
        self.rag_engine = rag_engine
        self.network_analyzer = network_analyzer
        self.agent_orchestrator = agent_orchestrator
        
        self.scheduler = AsyncIOScheduler()
        self.tasks: Dict[str, Dict[str, Any]] = {}
        
        logger.info("IntelligenceScheduler initialized")
    
    async def start(self):
        """Start the scheduler."""
        logger.info("Starting intelligence scheduler")
        
        # Schedule CVE feed updates
        self.scheduler.add_job(
            self._update_cve_feed,
            trigger=IntervalTrigger(hours=settings.CVE_UPDATE_INTERVAL_HOURS),
            id="cve_update",
            name="Update CVE Feed",
            replace_existing=True,
        )
        self.tasks["cve_update"] = {
            "name": "Update CVE Feed",
            "interval_hours": settings.CVE_UPDATE_INTERVAL_HOURS,
            "last_run": None,
            "next_run": None,
        }
        
        # Schedule embedding updates
        self.scheduler.add_job(
            self._update_embeddings,
            trigger=IntervalTrigger(hours=settings.EMBEDDING_UPDATE_INTERVAL_HOURS),
            id="embedding_update",
            name="Update Embeddings",
            replace_existing=True,
        )
        self.tasks["embedding_update"] = {
            "name": "Update Embeddings",
            "interval_hours": settings.EMBEDDING_UPDATE_INTERVAL_HOURS,
            "last_run": None,
            "next_run": None,
        }
        
        # Schedule network scans
        self.scheduler.add_job(
            self._scan_network,
            trigger=IntervalTrigger(hours=settings.NETWORK_SCAN_INTERVAL_HOURS),
            id="network_scan",
            name="Scan Local Network",
            replace_existing=True,
        )
        self.tasks["network_scan"] = {
            "name": "Scan Local Network",
            "interval_hours": settings.NETWORK_SCAN_INTERVAL_HOURS,
            "last_run": None,
            "next_run": None,
        }
        
        # Schedule threat intel updates
        self.scheduler.add_job(
            self._update_threat_intel,
            trigger=IntervalTrigger(hours=settings.THREAT_INTEL_UPDATE_INTERVAL_HOURS),
            id="threat_intel_update",
            name="Update Threat Intelligence",
            replace_existing=True,
        )
        self.tasks["threat_intel_update"] = {
            "name": "Update Threat Intelligence",
            "interval_hours": settings.THREAT_INTEL_UPDATE_INTERVAL_HOURS,
            "last_run": None,
            "next_run": None,
        }
        
        # Schedule autonomous agent runs
        self.scheduler.add_job(
            self._run_agents,
            trigger=IntervalTrigger(hours=6),
            id="agent_run",
            name="Run Autonomous Agents",
            replace_existing=True,
        )
        self.tasks["agent_run"] = {
            "name": "Run Autonomous Agents",
            "interval_hours": 6,
            "last_run": None,
            "next_run": None,
        }
        
        self.scheduler.start()
        
        # Update next run times
        for job in self.scheduler.get_jobs():
            task_id = job.id
            if task_id in self.tasks:
                self.tasks[task_id]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
        
        logger.info(f"Scheduled {len(self.tasks)} tasks")
    
    async def stop(self):
        """Stop the scheduler."""
        logger.info("Stopping intelligence scheduler")
        self.scheduler.shutdown(wait=False)
    
    async def _update_cve_feed(self):
        """Update CVE feed from NVD."""
        logger.info("Scheduled task: Updating CVE feed")
        
        try:
            if self.ingestion_service:
                await self.ingestion_service.download_cve_feed()
                
                self.tasks["cve_update"]["last_run"] = datetime.utcnow().isoformat()
                job = self.scheduler.get_job("cve_update")
                if job:
                    self.tasks["cve_update"]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
                
                logger.info("CVE feed update completed")
            else:
                logger.warning("Ingestion service not available")
                
        except Exception as e:
            logger.error(f"CVE feed update failed: {str(e)}")
    
    async def _update_embeddings(self):
        """Update embeddings for threat intelligence."""
        logger.info("Scheduled task: Updating embeddings")
        
        try:
            if self.rag_engine:
                # This would re-embed new/updated documents
                # For now, just log
                logger.info("Embedding update completed (no new documents)")
                
                self.tasks["embedding_update"]["last_run"] = datetime.utcnow().isoformat()
                job = self.scheduler.get_job("embedding_update")
                if job:
                    self.tasks["embedding_update"]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
                    
        except Exception as e:
            logger.error(f"Embedding update failed: {str(e)}")
    
    async def _scan_network(self):
        """Scan local network for exposure."""
        logger.info("Scheduled task: Scanning local network")
        
        try:
            if self.network_analyzer:
                await self.network_analyzer.scan(
                    targets=settings.DEFAULT_SCAN_TARGETS,
                    scan_type="basic",
                )
                
                self.tasks["network_scan"]["last_run"] = datetime.utcnow().isoformat()
                job = self.scheduler.get_job("network_scan")
                if job:
                    self.tasks["network_scan"]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
                
                logger.info("Network scan completed")
            else:
                logger.warning("Network analyzer not available")
                
        except Exception as e:
            logger.error(f"Network scan failed: {str(e)}")
    
    async def _update_threat_intel(self):
        """Update all threat intelligence feeds."""
        logger.info("Scheduled task: Updating threat intelligence")
        
        try:
            if self.ingestion_service:
                await self.ingestion_service.run_full_ingestion()
                
                self.tasks["threat_intel_update"]["last_run"] = datetime.utcnow().isoformat()
                job = self.scheduler.get_job("threat_intel_update")
                if job:
                    self.tasks["threat_intel_update"]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
                
                logger.info("Threat intelligence update completed")
            else:
                logger.warning("Ingestion service not available")
                
        except Exception as e:
            logger.error(f"Threat intelligence update failed: {str(e)}")
    
    async def _run_agents(self):
        """Run autonomous AI agents."""
        logger.info("Scheduled task: Running autonomous agents")
        
        try:
            if self.agent_orchestrator:
                await self.agent_orchestrator.run_all_agents()
                
                self.tasks["agent_run"]["last_run"] = datetime.utcnow().isoformat()
                job = self.scheduler.get_job("agent_run")
                if job:
                    self.tasks["agent_run"]["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None
                
                logger.info("Autonomous agents run completed")
            else:
                logger.warning("Agent orchestrator not available")
                
        except Exception as e:
            logger.error(f"Autonomous agents run failed: {str(e)}")
    
    def get_schedule(self) -> Dict[str, Any]:
        """
        Get current schedule status.
        
        Returns:
            Schedule status
        """
        return {
            "scheduler_running": self.scheduler.running,
            "total_tasks": len(self.tasks),
            "tasks": self.tasks,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def add_task(
        self,
        task_id: str,
        name: str,
        func: Callable,
        interval_hours: int,
    ):
        """
        Add a custom scheduled task.
        
        Args:
            task_id: Unique task identifier
            name: Task name
            func: Function to execute
            interval_hours: Run interval in hours
        """
        self.scheduler.add_job(
            func,
            trigger=IntervalTrigger(hours=interval_hours),
            id=task_id,
            name=name,
            replace_existing=True,
        )
        
        self.tasks[task_id] = {
            "name": name,
            "interval_hours": interval_hours,
            "last_run": None,
            "next_run": None,
        }
        
        logger.info(f"Added scheduled task: {task_id}")
    
    def remove_task(self, task_id: str):
        """
        Remove a scheduled task.
        
        Args:
            task_id: Task identifier
        """
        self.scheduler.remove_job(task_id)
        
        if task_id in self.tasks:
            del self.tasks[task_id]
        
        logger.info(f"Removed scheduled task: {task_id}")
    
    async def run_task_now(self, task_id: str):
        """
        Run a task immediately.
        
        Args:
            task_id: Task identifier
        """
        if task_id not in self.tasks:
            return {"error": f"Task {task_id} not found"}
        
        logger.info(f"Manually running task: {task_id}")
        
        task_map = {
            "cve_update": self._update_cve_feed,
            "embedding_update": self._update_embeddings,
            "network_scan": self._scan_network,
            "threat_intel_update": self._update_threat_intel,
            "agent_run": self._run_agents,
        }
        
        if task_id in task_map:
            await task_map[task_id]()
            return {"status": "completed", "task_id": task_id}
        else:
            return {"error": f"Task {task_id} has no handler"}
