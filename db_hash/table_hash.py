from hashlib import md5


class Node:
    def __init__(self, key, value) -> None:
        self.key = key
        self.value = value
        self.next = None


class Hashtable:
    def __init__(self) -> None:
        self.capacity = 1000
        self.buckets = [None] * self.capacity
        pass

    def hash(self, key):
        h = md5(key.encode()).hexdigest()
        return int(h, 16) % self.capacity

    def insert(self, key, value):
        index = self.hash(key)
        bucket = self.buckets[index]
        if self.buckets[index] is None:
            self.buckets[index] = Node(key, value)
        else:
            while bucket.next is not None:
                bucket = bucket.next
        bucket.next = Node(key, value)


hashtable = Hashtable()

hashtable.hash("смартфон")

hashtable.insert("смартфон", {'name': 'Iphone', 'price': 100000})
hashtable.insert("Ноутбуки", {'name': 'Samsung', 'price': 200000, })