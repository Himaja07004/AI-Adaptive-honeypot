from django.db import models

class AttackLog(models.Model):
    attacker_ip = models.CharField(max_length=45)
    target_path = models.CharField(max_length=255)
    payload = models.TextField()
    classified_intent = models.CharField(max_length=255)
    risk_score = models.FloatField(default=0.0)
    session_id = models.CharField(max_length=100, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.attacker_ip} - {self.classified_intent}"