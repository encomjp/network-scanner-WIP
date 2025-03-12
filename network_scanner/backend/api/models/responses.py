"""
API response models.

This module contains the response models for the API.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ApiResponse(BaseModel):
    """
    Standard API response model.
    
    This model is used for all API responses to ensure a consistent format.
    """
    
    success: bool = Field(
        ...,
        description="Whether the request was successful or not."
    )
    message: Optional[str] = Field(
        None,
        description="A message describing the result of the request."
    )
    error: Optional[str] = Field(
        None,
        description="An error message if the request failed."
    )
    data: Optional[Any] = Field(
        None,
        description="The data returned by the request."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "success": True,
                "message": "Request successful",
                "data": {
                    "key": "value"
                }
            }
        } 