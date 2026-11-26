from __future__ import annotations

from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str


class RoleBrief(BaseModel):
    id: int
    code: str
    name: str

    model_config = {"from_attributes": True}
