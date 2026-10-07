"""Borrow connection pools without sharing caller headers, cookies or identity.

Original prepared request, Session policy and send arguments remain authoritative.
Only the standard requests adapter is eligible. A shallow Session view owns its
adapter mapping; the caller's session and custom adapters are never mutated.
Pools belong to the worker thread and close at application shutdown.
"""
import copy,threading
import requests

class BorrowedPools:
    def __init__(self, original_send):
        self.original_send=original_send;self.local=threading.local();self.lock=threading.Lock();self.adapters=[]
    def send(self,session,request,**kwargs):
        original=session.get_adapter(request.url)
        if type(original) is not requests.adapters.HTTPAdapter:
            return self.original_send(session,request,**kwargs)
        adapter=getattr(self.local,'adapter',None)
        if adapter is None:
            adapter=requests.adapters.HTTPAdapter(pool_connections=32,pool_maxsize=4,pool_block=False)
            self.local.adapter=adapter
            with self.lock:self.adapters.append(adapter)
        view=copy.copy(session)
        view.adapters=session.adapters.copy()
        for prefix,current in session.adapters.items():
            if current is original:view.adapters[prefix]=adapter
        # Sharing ONLY this caller's own cookie jar preserves requests' cookie
        # updates. The pool has no cookie jar and no authentication/header state.
        return self.original_send(view,request,**kwargs)
    def close(self):
        with self.lock:
            for adapter in self.adapters:adapter.close()
            self.adapters.clear()
