# DistributedSystems

To run the server with:

1. At-most-once invocation semantic

```python server.py --semantics at-most-once```

2. At-least-once invocation semantic

```python server.py --semantics at-least-once```  

---
  
To run the client:

```python client.py --freshness FRESHNESS```

where FRESHNESS is the freshness interval of the cache, an integer. 

For example,

```python client.py --freshness 30```

runs the client with a freshness interval of 30 seconds.
