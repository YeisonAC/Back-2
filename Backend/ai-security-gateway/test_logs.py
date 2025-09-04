import requests
import json
from typing import Dict, Any, Optional

def print_json(title: str, data: Dict[str, Any]) -> None:
    """Helper function to print JSON data with a title"""
    print(f"\n{title}:" + "="*50)
    print(json.dumps(data, indent=2))
    print("="*60 + "\n")

def test_logs_endpoint(base_url: str, token: str) -> bool:
    """Test the logs endpoint with the given token"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print("\n" + "="*60)
    print(f"Testing logs endpoint at {base_url}")
    print("="*60)
    
    try:
        # First, test connection
        print("\n[1/2] Testing connection...")
        test_response = requests.get(f"{base_url}/health")
        print(f"  - Health check status: {test_response.status_code}")
        
        if test_response.status_code != 200:
            print(f"  ❌ Server is not responding correctly: {test_response.text}")
            return False
            
        # Test logs endpoint
        print("[2/2] Testing logs endpoint...")
        response = requests.get(
            f"{base_url}/api/logs",
            params={"page": 1, "page_size": 5},
            headers=headers,
            timeout=10
        )
        
        print(f"  - Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  - Found {data.get('total', 0)} total logs")
            print(f"  - Showing page {data.get('page', 1)} of {len(data.get('data', []))} items")
            
            # Print first log entry if available
            if data.get('data'):
                print("\nSample log entry:")
                print_json("First Log Entry", data['data'][0])
            
            return True
            
        else:
            error_msg = response.text
            print(f"  ❌ Error: {error_msg}")
            
            # Try to get more detailed error info
            try:
                error_data = response.json()
                print_json("Error Details", error_data)
            except:
                pass
                
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"  ❌ Request failed: {str(e)}")
        if isinstance(e, requests.exceptions.ConnectionError):
            print("  - Make sure the server is running and accessible")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {str(e)}")
        return False

def get_token_interactive() -> str:
    """Get token from user input"""
    print("\n" + "="*60)
    print("API Token Required")
    print("="*60)
    print("Please enter your authentication token.")
    print("This should be a valid JWT or API key.")
    return input("\nEnter your token: ").strip()

if __name__ == "__main__":
    # Configuration
    BASE_URL = "http://localhost:8001"
    
    # Get token from user
    token = get_token_interactive()
    
    # Run tests
    success = test_logs_endpoint(BASE_URL, token)
    
    # Print final result
    print("\n" + "="*60)
    if success:
        print("✅ Logs endpoint test completed successfully!")
    else:
        print("❌ Logs endpoint test failed. See above for details.")
    print("="*60)
