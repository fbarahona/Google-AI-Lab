"""
Building blocks of SocTicketingService, one responsibility per module:
- schema: the soc_tickets column contract, row conversion, persistence error
- writes: ticket persistence (dispatch, auto-closed archive, verdicts, backfill)
- queries: analyst queue and archive reads, incident roll-up
- metrics: dashboard KPIs and breakdowns
- seed_data: sample history for an empty local archive

The class itself is assembled in src.demo.soc_ticketing.ticketing_service.
"""
