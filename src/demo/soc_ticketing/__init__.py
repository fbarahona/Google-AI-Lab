"""
SOC Ticketing System Package.
"""
from .models import SocTicket
from .ticketing_service import SocTicketingService

__all__ = ["SocTicket", "SocTicketingService"]

