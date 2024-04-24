from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Game(models.Model):
    id = models.BigAutoField(primary_key=True)
    rank = models.IntegerField(_('Rank'), blank=True, null=True)
    photo = models.ImageField(_('Photo'), blank=True, null=True)
    rating = models.FloatField(_('Rating'), blank=True, null=True)
    date_create = models.DateTimeField(_('Date Created'), auto_now_add=True)
    name = models.CharField(_('Name'), max_length=255, blank=True, null=True)
    description = models.TextField(_('Description'), blank=True, null=True)
    date_release = models.DateTimeField(_('Date Released'), blank=True, null=True)
    date_finished = models.DateTimeField(_('Date Finished'), blank=True, null=True)


class Solution(models.Model):
    id = models.BigAutoField(primary_key=True)
    description = models.TextField(_('Description'), blank=True, null=True)


class Achievement(models.Model):
    id = models.BigAutoField(primary_key=True)
    photo = models.ImageField(_('Photo'), blank=True, null=True)
    name = models.CharField(_('Name'), max_length=255, blank=True, null=True)
    description = models.TextField(_('Description'), blank=True, null=True)
    date_finished = models.DateTimeField(_('Date Finished'), blank=True, null=True)
    game = models.ForeignKey(Game, on_delete=models.CASCADE)
    solutions = models.ManyToManyField(Solution, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['game']),
        ]


class Item(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(_('Name'), max_length=255)
    photo = models.ImageField(_('Photo'), blank=True, null=True)
    description = models.TextField(_('Description'), blank=True, null=True)


class Inventory(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(_('Name'), max_length=255)
    photo = models.ImageField(_('Photo'), blank=True, null=True)
    description = models.TextField(_('Description'), blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True)
    items = models.ManyToManyField(Item, blank=True)
    game = models.ForeignKey(Game, on_delete=models.CASCADE)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    games = models.ManyToManyField(Game, through='UserGameProfile')


class UserGameProfile(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    game = models.ForeignKey(Game, on_delete=models.CASCADE)
    inventory_progress = models.IntegerField(default=0)
    achievements_progress = models.IntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=['user_profile', 'game']),
        ]


class UserAchievement(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    achievement = models.ForeignKey(Achievement, on_delete=models.CASCADE)
    is_unlocked = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['user_profile', 'achievement']),
        ]


class UserInventory(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    inventory = models.ForeignKey(Inventory, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=['user_profile', 'inventory']),
        ]
