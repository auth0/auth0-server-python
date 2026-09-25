"""Shared test doubles for the stateless store contract."""


class OneSlotStore:
    """A StatelessStateStore fake with one physical slot per instance, where the identifier is an encryption salt rather than a location key."""

    def __init__(self):
        self.slot = None

    async def set(self, identifier, state, options=None):
        self.slot = (identifier, state)

    async def get(self, identifier, options=None):
        if not self.slot or self.slot[0] != identifier:
            return None
        return self.slot[1]

    async def delete(self, identifier, options=None):
        self.slot = None
