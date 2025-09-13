"""
Credits Management System (Standalone Version for Testing)
Handles credit deduction and management for API usage
"""

import os
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from supabase import create_client, Client

# Environment variables
CREDITS_TABLE = os.getenv("CREDITS_TABLE", "user_credits")
DEFAULT_CREDITS_PER_REQUEST = int(os.getenv("DEFAULT_CREDITS_PER_REQUEST", "1"))

def get_supabase():
    """Get Supabase client instance"""
    supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    supabase_anon_key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    
    if not supabase_url or not supabase_anon_key:
        return None
    
    try:
        return create_client(supabase_url, supabase_anon_key)
    except Exception as e:
        print(f"[SUPABASE] Error creating client: {e}")
        return None

class CreditsManager:
    """
    Manages user credits and deduction logic
    """
    
    def __init__(self):
        self.supabase = get_supabase()
        self.credits_table = CREDITS_TABLE
        self.default_credits_per_request = DEFAULT_CREDITS_PER_REQUEST
    
    def get_user_credits(self, user_id: str) -> Optional[int]:
        """
        Get current credit balance for a user
        
        Args:
            user_id: The user's ID
            
        Returns:
            Current credit balance or None if user not found
        """
        if not self.supabase:
            return None
            
        try:
            result = self.supabase.table(self.credits_table).select("credits").eq("user_id", user_id).single().execute()
            
            if result.data:
                return result.data.get("credits")
            return None
            
        except Exception as e:
            print(f"[CREDITS] Error getting user credits: {e}")
            return None
    
    def consume_credits(self, user_id: str, credits: int = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Consume credits for a user
        
        Args:
            user_id: The user's ID
            credits: Number of credits to consume (default: DEFAULT_CREDITS_PER_REQUEST)
            api_key_id: The API key ID used for the request
            
        Returns:
            Dict with success status and remaining credits
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        credits_to_consume = credits or self.default_credits_per_request
        
        try:
            # Get current credits
            current_credits = self.get_user_credits(user_id)
            
            if current_credits is None:
                return {"success": False, "error": "User not found"}
            
            if current_credits < credits_to_consume:
                return {
                    "success": False, 
                    "error": "Insufficient credits",
                    "required": credits_to_consume,
                    "available": current_credits
                }
            
            # Deduct credits
            new_credits = current_credits - credits_to_consume
            
            # Update credits in database
            update_data = {
                "credits": new_credits,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            if api_key_id:
                update_data["last_api_key_used"] = api_key_id
            
            result = self.supabase.table(self.credits_table).update(update_data).eq("user_id", user_id).execute()
            
            if result.data:
                print(f"[CREDITS] Consumed {credits_to_consume} credits from user {user_id}. Remaining: {new_credits}")
                return {
                    "success": True,
                    "remaining_credits": new_credits,
                    "consumed_credits": credits_to_consume
                }
            else:
                return {"success": False, "error": "Failed to update credits"}
                
        except Exception as e:
            print(f"[CREDITS] Error consuming credits: {e}")
            return {"success": False, "error": str(e)}
    
    def check_credits_before_request(self, user_id: str, required_credits: int = None) -> Dict[str, Any]:
        """
        Check if user has sufficient credits before processing a request
        
        Args:
            user_id: The user's ID
            required_credits: Number of credits required (default: DEFAULT_CREDITS_PER_REQUEST)
            
        Returns:
            Dict with success status and credit information
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        credits_needed = required_credits or self.default_credits_per_request
        
        try:
            current_credits = self.get_user_credits(user_id)
            
            if current_credits is None:
                return {"success": False, "error": "User not found"}
            
            if current_credits < credits_needed:
                return {
                    "success": False,
                    "error": "Insufficient credits",
                    "required": credits_needed,
                    "available": current_credits
                }
            
            return {
                "success": True,
                "available_credits": current_credits,
                "required_credits": credits_needed
            }
            
        except Exception as e:
            print(f"[CREDITS] Error checking credits: {e}")
            return {"success": False, "error": str(e)}
    
    def add_credits_to_user(self, user_id: str, credits: int, reason: str = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Add credits to a user's account
        
        Args:
            user_id: The user's ID
            credits: Number of credits to add
            reason: Reason for adding credits
            api_key_id: API key ID that initiated the transaction
            
        Returns:
            Dict with success status and new credit balance
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        try:
            # Get current credits
            current_credits = self.get_user_credits(user_id)
            
            if current_credits is None:
                # User doesn't exist, create them
                new_credits = credits
                user_data = {
                    "user_id": user_id,
                    "credits": new_credits,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
                
                if api_key_id:
                    user_data["last_api_key_used"] = api_key_id
                
                result = self.supabase.table(self.credits_table).insert(user_data).execute()
                
                if result.data:
                    print(f"[CREDITS] Created user {user_id} with {new_credits} credits")
                    return {
                        "success": True,
                        "new_credits": new_credits,
                        "added_credits": credits,
                        "user_created": True
                    }
                else:
                    return {"success": False, "error": "Failed to create user"}
            else:
                # User exists, add credits
                new_credits = current_credits + credits
                
                update_data = {
                    "credits": new_credits,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
                
                if api_key_id:
                    update_data["last_api_key_used"] = api_key_id
                
                result = self.supabase.table(self.credits_table).update(update_data).eq("user_id", user_id).execute()
                
                if result.data:
                    print(f"[CREDITS] Added {credits} credits to user {user_id}. New balance: {new_credits}")
                    return {
                        "success": True,
                        "new_credits": new_credits,
                        "added_credits": credits,
                        "user_created": False
                    }
                else:
                    return {"success": False, "error": "Failed to update credits"}
                    
        except Exception as e:
            print(f"[CREDITS] Error adding credits: {e}")
            return {"success": False, "error": str(e)}

# Global instance
credits_manager = CreditsManager()

# Convenience functions
def consume_credits(user_id: str, credits: int = None, api_key_id: str = None) -> Dict[str, Any]:
    """
    Convenience function to consume credits
    
    Args:
        user_id: The user's ID
        credits: Number of credits to consume
        api_key_id: The API key ID used
        
    Returns:
        Dict with operation result
    """
    return credits_manager.consume_credits(user_id, credits, api_key_id)

def check_credits_before_request(user_id: str, required_credits: int = None) -> Dict[str, Any]:
    """
    Convenience function to check credits before request
    
    Args:
        user_id: The user's ID
        required_credits: Number of credits required
        
    Returns:
        Dict with check result
    """
    return credits_manager.check_credits_before_request(user_id, required_credits)

def get_user_credits(user_id: str) -> Optional[int]:
    """
    Convenience function to get user credits
    
    Args:
        user_id: The user's ID
        
    Returns:
        Current credit balance or None
    """
    return credits_manager.get_user_credits(user_id)

def add_credits_to_user(user_id: str, credits: int, reason: str = None, api_key_id: str = None) -> Dict[str, Any]:
    """
    Convenience function to add credits to user
    
    Args:
        user_id: The user's ID
        credits: Number of credits to add
        reason: Reason for adding credits
        api_key_id: API key ID that initiated the transaction
        
    Returns:
        Dict with operation result
    """
    return credits_manager.add_credits_to_user(user_id, credits, reason, api_key_id)
