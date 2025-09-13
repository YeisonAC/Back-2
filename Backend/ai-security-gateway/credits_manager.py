"""
Token Management System
Handles token consumption and management for API usage with plan-based limits
"""

import os
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from supabase import create_client, Client

from supabase_client import get_supabase

# Environment variables
TOKENS_TABLE = os.getenv("TOKENS_TABLE", "user_tokens")
PLANS_TABLE = os.getenv("PLANS_TABLE", "plans")
TOKEN_TRANSACTIONS_TABLE = os.getenv("TOKEN_TRANSACTIONS_TABLE", "token_transactions")

# Plan configurations
PLAN_CONFIGS = {
    "Free": {
        "token_limit": 1000,
        "description": "Plan gratuito con 1000 tokens"
    },
    "Pro": {
        "token_limit": 50000,
        "description": "Plan profesional con 50000 tokens"
    }
}


class TokenManager:
    """
    Manages user tokens and consumption logic with plan-based limits
    """
    
    def __init__(self):
        self.supabase = get_supabase()
        self.tokens_table = TOKENS_TABLE
        self.plans_table = PLANS_TABLE
        self.token_transactions_table = TOKEN_TRANSACTIONS_TABLE
    
    def get_user_plan(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user's plan information
        
        Args:
            user_id: The user's ID
            
        Returns:
            Plan information or None if user not found
        """
        if not self.supabase:
            return None
            
        try:
            # Get user with plan information
            result = self.supabase.table(self.tokens_table).select("*, plans(*)").eq("user_id", user_id).single().execute()
            
            if result.data:
                plan_info = result.data.get("plans", {})
                return {
                    "plan_id": result.data.get("plan_id"),
                    "plan_name": plan_info.get("name", "Free"),
                    "token_limit": plan_info.get("token_limit", 1000),
                    "description": plan_info.get("description", "Plan gratuito")
                }
            return None
            
        except Exception as e:
            print(f"[TOKENS] Error getting user plan: {e}")
            return None
    
    def get_user_tokens_used(self, user_id: str) -> Optional[int]:
        """
        Get current token usage for a user
        
        Args:
            user_id: The user's ID
            
        Returns:
            Current token usage or None if user not found
        """
        if not self.supabase:
            return None
            
        try:
            result = self.supabase.table(self.tokens_table).select("tokens_used").eq("user_id", user_id).single().execute()
            
            if result.data:
                return result.data.get("tokens_used", 0)
            return None
            
        except Exception as e:
            print(f"[TOKENS] Error getting user tokens used: {e}")
            return None
    
    def get_remaining_tokens(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get remaining tokens for a user based on their plan
        
        Args:
            user_id: The user's ID
            
        Returns:
            Dict with remaining tokens and plan info
        """
        user_plan = self.get_user_plan(user_id)
        tokens_used = self.get_user_tokens_used(user_id)
        
        if not user_plan or tokens_used is None:
            return None
        
        remaining = max(0, user_plan["token_limit"] - tokens_used)
        
        return {
            "remaining_tokens": remaining,
            "tokens_used": tokens_used,
            "token_limit": user_plan["token_limit"],
            "plan_name": user_plan["plan_name"],
            "usage_percentage": round((tokens_used / user_plan["token_limit"]) * 100, 2) if user_plan["token_limit"] > 0 else 0
        }
    
    def check_token_limit_before_request(self, user_id: str, estimated_tokens: int) -> Dict[str, Any]:
        """
        Check if user has enough tokens for a request
        
        Args:
            user_id: The user's ID
            estimated_tokens: Estimated tokens for the request
            
        Returns:
            Dict with success status and remaining tokens
        """
        remaining_info = self.get_remaining_tokens(user_id)
        
        if not remaining_info:
            return {"success": False, "error": "User not found"}
        
        remaining_tokens = remaining_info["remaining_tokens"]
        
        if remaining_tokens < estimated_tokens:
            return {
                "success": False, 
                "error": f"Insufficient tokens. Required: {estimated_tokens}, Available: {remaining_tokens}",
                "required": estimated_tokens,
                "available": remaining_tokens,
                "plan_info": remaining_info
            }
        
        return {
            "success": True,
            "remaining_tokens": remaining_tokens - estimated_tokens,
            "plan_info": remaining_info
        }
    
    def consume_tokens(self, user_id: str, tokens: int, api_key_id: str = None) -> Dict[str, Any]:
        """
        Consume tokens for a user
        
        Args:
            user_id: The user's ID
            tokens: Number of tokens to consume
            api_key_id: The API key ID used for the request
            
        Returns:
            Dict with success status and remaining tokens
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        if tokens <= 0:
            return {"success": False, "error": "Invalid token amount"}
        
        try:
            # Check token limit before consuming
            limit_check = self.check_token_limit_before_request(user_id, tokens)
            if not limit_check["success"]:
                return limit_check
            
            # Get current token usage
            current_usage = self.get_user_tokens_used(user_id)
            if current_usage is None:
                return {"success": False, "error": "User not found"}
            
            # Calculate new usage
            new_usage = current_usage + tokens
            
            # Update token usage in database
            update_data = {
                "tokens_used": new_usage,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            if api_key_id:
                update_data["last_api_key_used"] = api_key_id
            
            result = self.supabase.table(self.tokens_table).update(update_data).eq("user_id", user_id).execute()
            
            if result.data:
                print(f"[TOKENS] Consumed {tokens} tokens from user {user_id}. Total used: {new_usage}")
                
                # Record transaction
                self._record_token_transaction(user_id, tokens, "consumption", api_key_id)
                
                remaining_info = self.get_remaining_tokens(user_id)
                return {
                    "success": True,
                    "tokens_consumed": tokens,
                    "total_tokens_used": new_usage,
                    "remaining_tokens": remaining_info["remaining_tokens"] if remaining_info else 0,
                    "plan_info": remaining_info
                }
            else:
                return {"success": False, "error": "Failed to update token usage"}
            
        except Exception as e:
            print(f"[TOKENS] Error consuming tokens: {e}")
            return {"success": False, "error": str(e)}
    
    def add_tokens_to_user(self, user_id: str, tokens: int, reason: str = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Add tokens to a user (for admin operations or plan upgrades)
        
        Args:
            user_id: The user's ID
            tokens: Number of tokens to add (negative to reduce)
            reason: Reason for the token adjustment
            api_key_id: The API key ID used for the request
            
        Returns:
            Dict with success status and new token info
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        try:
            # Get current token usage
            current_usage = self.get_user_tokens_used(user_id)
            if current_usage is None:
                return {"success": False, "error": "User not found"}
            
            # Calculate new usage (ensure it doesn't go below 0)
            new_usage = max(0, current_usage + tokens)
            actual_tokens_added = new_usage - current_usage
            
            # Update token usage in database
            update_data = {
                "tokens_used": new_usage,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            result = self.supabase.table(self.tokens_table).update(update_data).eq("user_id", user_id).execute()
            
            if result.data:
                print(f"[TOKENS] Added {actual_tokens_added} tokens to user {user_id}. New usage: {new_usage}")
                
                # Record transaction
                self._record_token_transaction(user_id, actual_tokens_added, "adjustment", api_key_id, reason)
                
                remaining_info = self.get_remaining_tokens(user_id)
                return {
                    "success": True,
                    "tokens_added": actual_tokens_added,
                    "total_tokens_used": new_usage,
                    "remaining_tokens": remaining_info["remaining_tokens"] if remaining_info else 0,
                    "plan_info": remaining_info,
                    "reason": reason
                }
            else:
                return {"success": False, "error": "Failed to update token usage"}
            
        except Exception as e:
            print(f"[TOKENS] Error adding tokens: {e}")
            return {"success": False, "error": str(e)}
    
    def _record_token_transaction(self, user_id: str, tokens: int, transaction_type: str, api_key_id: str = None, reason: str = None):
        """
        Record a token transaction in the transaction history
        """
        if not self.supabase:
            return
        
        try:
            transaction_data = {
                "user_id": user_id,
                "tokens": tokens,
                "transaction_type": transaction_type,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            if api_key_id:
                transaction_data["api_key_id"] = api_key_id
            
            if reason:
                transaction_data["reason"] = reason
            
            self.supabase.table(self.token_transactions_table).insert(transaction_data).execute()
            
        except Exception as e:
            print(f"[TOKENS] Error recording token transaction: {e}")
    
    def get_user_token_history(self, user_id: str, limit: int = 50) -> Optional[list]:
        """
        Get token transaction history for a user
        
        Args:
            user_id: The user's ID
            limit: Maximum number of transactions to return
            
        Returns:
            List of transactions or None if error
        """
        if not self.supabase:
            return None
        
        try:
            result = self.supabase.table(self.token_transactions_table).select("*").eq("user_id", user_id).order("created_at", desc=True).limit(limit).execute()
            
            if result.data:
                return result.data
            return []
            
        except Exception as e:
            print(f"[TOKENS] Error getting token history: {e}")
            return None
    
    # Legacy methods for backward compatibility
    def get_user_credits(self, user_id: str) -> Optional[int]:
        """
        Legacy method - returns remaining tokens as credits
        """
        remaining_info = self.get_remaining_tokens(user_id)
        return remaining_info["remaining_tokens"] if remaining_info else None
    
    def consume_credits(self, user_id: str, credits: int = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Legacy method - consumes tokens as credits
        """
        tokens_to_consume = credits or 1
        return self.consume_tokens(user_id, tokens_to_consume, api_key_id)
    
    def check_credits_before_request(self, user_id: str, required_credits: int = None) -> Dict[str, Any]:
        """
        Legacy method - checks token limit as credit check
        """
        estimated_tokens = required_credits or 1
        return self.check_token_limit_before_request(user_id, estimated_tokens)
    
    def add_credits_to_user(self, user_id: str, credits: int, reason: str = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Legacy method - adds tokens as credits
        """
        return self.add_tokens_to_user(user_id, credits, reason, api_key_id)


# Global instance
token_manager = TokenManager()


# Convenience functions for tokens
def consume_tokens(user_id: str, tokens: int, api_key_id: str = None) -> Dict[str, Any]:
    """
    Convenience function to consume tokens
    
    Args:
        user_id: The user's ID
        tokens: Number of tokens to consume
        api_key_id: The API key ID used
        
    Returns:
        Dict with operation result
    """
    return token_manager.consume_tokens(user_id, tokens, api_key_id)


def check_token_limit_before_request(user_id: str, estimated_tokens: int) -> Dict[str, Any]:
    """
    Convenience function to check token limit before request
    
    Args:
        user_id: The user's ID
        estimated_tokens: Estimated tokens for the request
        
    Returns:
        Dict with check result
    """
    return token_manager.check_token_limit_before_request(user_id, estimated_tokens)


def get_remaining_tokens(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get remaining tokens
    
    Args:
        user_id: The user's ID
        
    Returns:
        Dict with remaining tokens and plan info
    """
    return token_manager.get_remaining_tokens(user_id)


def get_user_plan(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get user plan
    
    Args:
        user_id: The user's ID
        
    Returns:
        Plan information or None
    """
    return token_manager.get_user_plan(user_id)


# Legacy convenience functions for backward compatibility
def consume_credits(user_id: str, credits: int = None, api_key_id: str = None) -> Dict[str, Any]:
    """
    Legacy convenience function to consume credits
    
    Args:
        user_id: The user's ID
        credits: Number of credits to consume
        api_key_id: The API key ID used
        
    Returns:
        Dict with operation result
    """
    return token_manager.consume_credits(user_id, credits, api_key_id)


def check_credits_before_request(user_id: str, required_credits: int = None) -> Dict[str, Any]:
    """
    Legacy convenience function to check credits before request
    
    Args:
        user_id: The user's ID
        required_credits: Number of credits required
        
    Returns:
        Dict with check result
    """
    return token_manager.check_credits_before_request(user_id, required_credits)


def get_user_credits(user_id: str) -> Optional[int]:
    """
    Legacy convenience function to get user credits
    
    Args:
        user_id: The user's ID
        
    Returns:
        Current credit balance or None
    """
    return token_manager.get_user_credits(user_id)


def _estimate_tokens(text: str) -> int:
    """
    Estimate tokens based on text input
    Simple approximation: ~4 characters = 1 token
    
    Args:
        text: Input text to estimate tokens for
        
    Returns:
        Estimated token count
    """
    if not text:
        return 0
    
    # Simple approximation: ~4 characters = 1 token
    # This is a rough estimate - in production you'd use a proper tokenizer
    char_count = len(text)
    estimated_tokens = max(1, char_count // 4)
    
    # Add buffer for response tokens (typically 20-30% of input)
    estimated_tokens = int(estimated_tokens * 1.3)
    
    return estimated_tokens
