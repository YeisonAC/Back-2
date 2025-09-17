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
SUBSCRIPTIONS_TABLE = os.getenv("SUBSCRIPTIONS_TABLE", "suscriptions")
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
    Manages user tokens and consumption logic with subscription-based limits
    """
    
    def __init__(self):
        self.supabase = get_supabase()
        self.subscriptions_table = SUBSCRIPTIONS_TABLE
        self.plans_table = PLANS_TABLE
        self.token_transactions_table = TOKEN_TRANSACTIONS_TABLE
    
    def get_user_plan(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user's plan information from subscriptions table
        
        Args:
            user_id: The user's ID
            
        Returns:
            Plan information or None if user not found
        """
        if not self.supabase:
            return None
        
        try:
            # Get user subscription with plan information
            result = self.supabase.table(self.subscriptions_table).select("*, plans(*)").eq("owner_id", user_id).eq("owner_type", "user").eq("status", "active").single().execute()
            
            if result.data:
                subscription = result.data
                plan_info = subscription.get("plans", {})
                return {
                    "plan_id": subscription.get("plan_id"),
                    "plan_name": plan_info.get("name", "Free"),
                    "token_limit": plan_info.get("token_limit", 1000),
                    "description": plan_info.get("description", "Plan gratuito"),
                    "subscription_id": subscription.get("id"),
                    "status": subscription.get("status"),
                    "current_period_end": subscription.get("current_period_end"),
                    "remaining_credits": subscription.get("remaining_credits", 0),
                    "total_credits": subscription.get("total_credits", 0),
                    "reset_date": subscription.get("reset_date")
                }
            else:
                return None
                
        except Exception as e:
            print(f"[TOKENS] Error getting user subscription: {e}")
            return None
    
    def get_user_tokens_used(self, user_id: str) -> Optional[int]:
        """
        Get current token usage for a user based on subscription
        
        Args:
            user_id: The user's ID
            
        Returns:
            Current token usage or None if user not found
        """
        if not self.supabase:
            return None
            
        try:
            # Get subscription to calculate tokens used
            result = self.supabase.table(self.subscriptions_table).select("total_credits, remaining_credits").eq("owner_id", user_id).eq("owner_type", "user").eq("status", "active").single().execute()
            
            if result.data:
                total_credits = result.data.get("total_credits", 0)
                remaining_credits = result.data.get("remaining_credits", 0)
                tokens_used = max(0, total_credits - remaining_credits)
                return tokens_used
            return None
            
        except Exception as e:
            print(f"[TOKENS] Error getting user tokens used: {e}")
            return None
    
    def get_remaining_tokens(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get remaining tokens for a user based on their subscription
        
        Args:
            user_id: The user's ID
            
        Returns:
            Dict with remaining tokens and plan info
        """
        user_plan = self.get_user_plan(user_id)
        
        if not user_plan:
            return None
        
        # Use remaining_credits from subscription
        remaining_credits = user_plan.get("remaining_credits", 0)
        total_credits = user_plan.get("total_credits", 0)
        tokens_used = max(0, total_credits - remaining_credits)
        
        return {
            "remaining_tokens": remaining_credits,
            "tokens_used": tokens_used,
            "token_limit": total_credits,
            "plan_name": user_plan["plan_name"],
            "usage_percentage": round((tokens_used / total_credits) * 100, 2) if total_credits > 0 else 0,
            "subscription_info": {
                "subscription_id": user_plan.get("subscription_id"),
                "status": user_plan.get("status"),
                "current_period_end": user_plan.get("current_period_end"),
                "reset_date": user_plan.get("reset_date")
            }
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
        Consume tokens for a user by updating remaining_credits in subscriptions table
        
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
            
            # Get current subscription info
            subscription_info = self.get_user_plan(user_id)
            if not subscription_info:
                return {"success": False, "error": "User subscription not found"}
            
            # Calculate new remaining credits
            current_remaining = subscription_info.get("remaining_credits", 0)
            new_remaining = max(0, current_remaining - tokens)
            
            # Update remaining_credits in subscriptions table
            update_data = {
                "remaining_credits": new_remaining,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            subscription_id = subscription_info.get("subscription_id")
            result = self.supabase.table(self.subscriptions_table).update(update_data).eq("id", subscription_id).execute()
            
            if result.data:
                print(f"[TOKENS] Consumed {tokens} tokens from user {user_id}. Remaining: {new_remaining}")
                
                # Record transaction
                self._record_token_transaction(user_id, tokens, "consumption", api_key_id)
                
                remaining_info = self.get_remaining_tokens(user_id)
                return {
                    "success": True,
                    "tokens_consumed": tokens,
                    "remaining_tokens": new_remaining,
                    "plan_info": remaining_info
                }
            else:
                return {"success": False, "error": "Failed to update subscription credits"}
            
        except Exception as e:
            print(f"[TOKENS] Error consuming tokens: {e}")
            return {"success": False, "error": str(e)}
    
    def add_tokens_to_user(self, user_id: str, tokens: int, reason: str = None, api_key_id: str = None) -> Dict[str, Any]:
        """
        Add tokens to a user by updating remaining_credits in subscriptions table
        
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
            # Get current subscription info
            subscription_info = self.get_user_plan(user_id)
            if not subscription_info:
                return {"success": False, "error": "User subscription not found"}
            
            # Calculate new remaining credits
            current_remaining = subscription_info.get("remaining_credits", 0)
            total_credits = subscription_info.get("total_credits", 0)
            new_remaining = max(0, min(total_credits, current_remaining + tokens))
            actual_tokens_added = new_remaining - current_remaining
            
            # Update remaining_credits in subscriptions table
            update_data = {
                "remaining_credits": new_remaining,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            subscription_id = subscription_info.get("subscription_id")
            result = self.supabase.table(self.subscriptions_table).update(update_data).eq("id", subscription_id).execute()
            
            if result.data:
                print(f"[TOKENS] Added {actual_tokens_added} tokens to user {user_id}. New remaining: {new_remaining}")
                
                # Record transaction
                self._record_token_transaction(user_id, actual_tokens_added, "adjustment", api_key_id, reason)
                
                remaining_info = self.get_remaining_tokens(user_id)
                return {
                    "success": True,
                    "tokens_added": actual_tokens_added,
                    "remaining_tokens": new_remaining,
                    "plan_info": remaining_info,
                    "reason": reason
                }
            else:
                return {"success": False, "error": "Failed to update subscription credits"}
            
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
    
    def create_user_subscription(self, user_id: str, plan_id: int = 1, owner_type: str = "user") -> Dict[str, Any]:
        """
        Create a new subscription for a user with Free plan by default
        
        Args:
            user_id: The user's ID
            plan_id: The plan ID (1 for Free, 2 for Pro)
            owner_type: Type of owner (user, organization, etc.)
            
        Returns:
            Dict with success status and subscription info
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        try:
            # Get plan information
            plan_result = self.supabase.table(self.plans_table).select("*").eq("id", plan_id).single().execute()
            
            if not plan_result.data:
                return {"success": False, "error": "Plan not found"}
            
            plan_info = plan_result.data
            token_limit = plan_info.get("token_limit", 1000)
            
            # Calculate dates
            now = datetime.now(timezone.utc)
            current_period_end = now.replace(year=now.year + 1) if plan_id == 2 else now.replace(month=now.month + 1)  # Pro: 1 year, Free: 1 month
            reset_date = now.replace(day=1, month=now.month + 1)  # Reset on first day of next month
            
            # Create subscription
            subscription_data = {
                "owner_type": owner_type,
                "owner_id": user_id,
                "plan_id": plan_id,
                "status": "active",
                "current_period_end": current_period_end.isoformat(),
                "created_at": now.isoformat(),
                "remaining_credits": token_limit,  # Start with full credits
                "total_credits": token_limit,
                "reset_date": reset_date.isoformat()
            }
            
            result = self.supabase.table(self.subscriptions_table).insert(subscription_data).execute()
            
            if result.data:
                subscription_id = result.data[0].get("id")
                print(f"[SUBSCRIPTION] Created subscription {subscription_id} for user {user_id} with plan {plan_info.get('name', 'Free')}")
                
                return {
                    "success": True,
                    "subscription_id": subscription_id,
                    "plan_name": plan_info.get("name", "Free"),
                    "token_limit": token_limit,
                    "remaining_credits": token_limit,
                    "total_credits": token_limit,
                    "status": "active",
                    "current_period_end": current_period_end.isoformat(),
                    "reset_date": reset_date.isoformat()
                }
            else:
                return {"success": False, "error": "Failed to create subscription"}
                
        except Exception as e:
            print(f"[SUBSCRIPTION] Error creating subscription: {e}")
            return {"success": False, "error": str(e)}
    
    def upgrade_user_subscription(self, user_id: str, new_plan_id: int) -> Dict[str, Any]:
        """
        Upgrade user subscription to a new plan
        
        Args:
            user_id: The user's ID
            new_plan_id: The new plan ID (1 for Free, 2 for Pro)
            
        Returns:
            Dict with success status and updated subscription info
        """
        if not self.supabase:
            return {"success": False, "error": "Supabase not available"}
        
        try:
            # Get current subscription
            current_subscription = self.get_user_plan(user_id)
            if not current_subscription:
                return {"success": False, "error": "No active subscription found"}
            
            # Get new plan information
            plan_result = self.supabase.table(self.plans_table).select("*").eq("id", new_plan_id).single().execute()
            
            if not plan_result.data:
                return {"success": False, "error": "New plan not found"}
            
            new_plan_info = plan_result.data
            new_token_limit = new_plan_info.get("token_limit", 1000)
            
            # Calculate dates
            now = datetime.now(timezone.utc)
            current_period_end = now.replace(year=now.year + 1) if new_plan_id == 2 else now.replace(month=now.month + 1)
            reset_date = now.replace(day=1, month=now.month + 1)
            
            # Update subscription
            subscription_id = current_subscription.get("subscription_id")
            update_data = {
                "plan_id": new_plan_id,
                "status": "active",
                "current_period_end": current_period_end.isoformat(),
                "updated_at": now.isoformat(),
                "total_credits": new_token_limit,
                "remaining_credits": new_token_limit,  # Reset to full credits on upgrade
                "reset_date": reset_date.isoformat()
            }
            
            result = self.supabase.table(self.subscriptions_table).update(update_data).eq("id", subscription_id).execute()
            
            if result.data:
                print(f"[SUBSCRIPTION] Upgraded user {user_id} to plan {new_plan_info.get('name', 'Unknown')}")
                
                return {
                    "success": True,
                    "subscription_id": subscription_id,
                    "plan_name": new_plan_info.get("name", "Unknown"),
                    "token_limit": new_token_limit,
                    "remaining_credits": new_token_limit,
                    "total_credits": new_token_limit,
                    "status": "active",
                    "current_period_end": current_period_end.isoformat(),
                    "reset_date": reset_date.isoformat()
                }
            else:
                return {"success": False, "error": "Failed to upgrade subscription"}
                
        except Exception as e:
            print(f"[SUBSCRIPTION] Error upgrading subscription: {e}")
            return {"success": False, "error": str(e)}
    
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
