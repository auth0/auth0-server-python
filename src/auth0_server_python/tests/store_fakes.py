"""Shared test doubles for the stateless store contract."""


class OneSlotStore:
    """Models a StatelessStateStore where the store identifier is an
    encryption salt, not a location key.

    One physical slot per instance, so a mismatched identifier reads as
    absent, not as a different record. AsyncMock cannot exercise this
    collision because it treats every identifier as a distinct key, so this
    fake is required instead.
    """

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
