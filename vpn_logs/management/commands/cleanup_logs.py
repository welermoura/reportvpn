from django.core.management.base import BaseCommand
from django.utils import timezone
from vpn_logs.models import VPNLog
from datetime import timedelta

class Command(BaseCommand):
    help = 'Removes VPN logs older than 6 months'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simulate deletion without actually removing records',
        )

    def handle(self, *args, **options):
        # Calculate retention date (6 months ~ 180 days)
        cutoff_date = timezone.now() - timedelta(days=180)
        
        # Query logs older than cutoff
        old_logs = VPNLog.objects.filter(start_time__lt=cutoff_date)
        count = old_logs.count()
        
        if options['dry_run']:
            self.stdout.write(self.style.SUCCESS(
                f'[DRY RUN] Found {count} logs older than {cutoff_date.date()} that would be deleted.'
            ))
        else:
            if count > 0:
                deleted, _ = old_logs.delete()
                self.stdout.write(self.style.SUCCESS(
                    f'Successfully deleted {count} logs older than {cutoff_date.date()}.'
                ))
            else:
                self.stdout.write(self.style.SUCCESS('No logs found specifically older than 6 months.'))
