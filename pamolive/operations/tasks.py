from celery import shared_task

from .services import execute_rotation, schedule_due_rotations


@shared_task
def execute_rotation_job(job_id):
    return execute_rotation(job_id).status


@shared_task
def dispatch_due_rotation_jobs():
    jobs = schedule_due_rotations()
    for job in jobs:
        execute_rotation_job.delay(str(job.pk))
    return len(jobs)
