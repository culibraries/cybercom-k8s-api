__author__ = 'mstacy'
import json
import math
import collections
from bson.objectid import ObjectId
from bson.code import Code
from operator import itemgetter

from collections import OrderedDict
from rest_framework.templatetags.rest_framework import replace_query_param


def MongoDistinct(field, DB_MongoClient, database, collection, query=None):
    if len(field.split(',')) > 1:
        group = {}
        for itm in field.split(','):
            group[itm.replace('.', '---')] = "${0}".format(itm)
        aggregate = [{"$group": {"_id": group}}]
        iresult = MongoAggregate(
            json.dumps(aggregate), DB_MongoClient, database, collection, query=query)
        result = []
        for itm in iresult:
            temp = itm['_id']
            trans = {}
            for k, v in temp.items():
                trans[k.replace('---', '.')] = v
            result.append(trans)
        return result
    db = DB_MongoClient
    if query:
        try:
            query = json.loads(query)
        except:
            raise Exception("Query: JSON object could be decoded")
        return db[database][collection].find(**query).distinct(field)
    return db[database][collection].distinct(field)


def MongoAggregate(aggregate, DB_MongoClient, database, collection, query=None):
    match = None
    if query:
        try:
            query = json.loads(query)
            query["$match"] = query['filter']
            del query['filter']
        except:
            raise Exception("Query: JSON object could be decoded")
    try:
        aggregate = json.loads(aggregate)
        if query:
            aggregate.insert(0, query)
    except:
        raise Exception("Aggregate: JSON object could be decoded")

    db = DB_MongoClient[database][collection]
    results = db.aggregate(aggregate)
    return results


def MongoGroupby(variable, groupby, DB_MongoClient, database, collection, query=None):
    if query:
        try:
            query = json.loads(query)
        except:
            raise Exception("Query: JSON object could be decoded")
    db = DB_MongoClient[database][collection]
    reducer = Code(
        " function(obj,prev) {prev.Sum += obj.%s;prev.count+=1; prev.Avg = prev.Sum/prev.count;}" % (variable))
    results = db.group(groupby, query, {
                       'Sum': 0, 'Avg': 0, 'count': 0, 'Variable': variable}, reducer)
    data_out = []
    try:
        data_out = multikeysort(results, groupby)
    except:
        data_out = results
    return data_out


def multikeysort(self, items, columns):
    comparers = [((itemgetter(col[1:].strip()), -1) if col.startswith('-')
                  else (itemgetter(col.strip()), 1)) for col in columns]

    def comparer(left, right):
        for fn, mult in comparers:
            result = cmp(fn(left), fn(right))
            if result:
                return mult * result
            else:
                return 0
    return sorted(items, cmp=comparer)


def set_pagination_vars(count, page, nPerPage):
    if nPerPage == 0:
        page = 1
        offset = 0
        max_page = 1
    else:
        max_page = math.ceil(float(count) / nPerPage)
        # Page min is 1
        if page < 1:
            page = 1
        # Change page to last page with data
        if page * nPerPage > count:
            page = int(max_page)
        # Cover count =0
        if page < 1:
            page = 1
        offset = (page - 1) * nPerPage
    return page, offset, max_page


def set_next_prev_urls(page, max_page, uri):
    if page < max_page:
        nexturi = replace_query_param(uri, 'page', page + 1)
    else:
        nexturi = None
    if page > 1:
        previous = replace_query_param(uri, 'page', page - 1)
    else:
        previous = None
    return nexturi, previous


def MongoDataPagination(DB_MongoClient, database, collection, query=None, page=1, nPerPage=None, uri=''):
    db = DB_MongoClient
    if query:
        try:
            query = json.loads(query)
        except:
            raise Exception("Query: JSON object could be decoded")

        count = db[database][collection].find(**query).count()
        # set page variables
        page, offset, max_page = set_pagination_vars(count, page, nPerPage)
        # Data
        data = [row for row in db[database][collection].find(
            **query).skip(offset).limit(nPerPage)]
    else:
        count = db[database][collection].find().count()
        # set page variables
        page, offset, max_page = set_pagination_vars(count, page, nPerPage)
        # Data
        data = [row for row in db[database]
                [collection].find().skip(offset).limit(nPerPage)]
    nexturi, previous = set_next_prev_urls(page, max_page, uri)

    result = {'count': count, 'meta': {'page': page, 'page_size': nPerPage, 'pages': int(max_page)}, 'next': nexturi,
              'previous': previous, 'results': data}
    # keep sort order
    try:
        od = collections.OrderedDict(sorted(result.items()))
    except:
        # older python versions < 2.7
        od = OrderedDict(sorted(result.items()))
    return od


def MongoDataInsert(DB_MongoClient, database, collection, data):
    db = DB_MongoClient
    # Update if data already in collection
    if '_id' in data:
        id = data['_id']
        return MongoDataSave(DB_MongoClient, database, collection, id, data)
    return db[database][collection].insert(data)
    if type(data) == type([]):
        return db[database][collection].insertMany(data)
    else:
        return db[database][collection].insertOne(data)


def MongoDataGet(DB_MongoClient, database, collection, id):
    db = DB_MongoClient
    id_types = get_id_types(id)
    for term_id in id_types:
        try:
            data = db[database][collection].find_one({'_id': term_id})
            if data:
                return data
        except:
            pass
    return {"Error": "DATA RECORD NOT FOUND"}


def MongoDataDelete(DB_MongoClient, database, collection, id):
    db = DB_MongoClient
    id_types = get_id_types(id)
    for term_id in id_types:
        result = db[database][collection].delete_one({'_id': term_id})
        if result.deleted_count:
            return result
    # else:
    #    return db[database][collection].delete_one({'_id':id})


def MongoDataSave(DB_MongoClient, database, collection, id, data):
    db = DB_MongoClient
    if db[database][collection].find_one({'_id': ObjectId(id)}):
        data['_id'] = ObjectId(id)
        return db[database][collection].save(data)
    elif db[database][collection].find_one({'_id': id}):
        return db[database][collection].save(data)
    else:
        return {"Error": "UNABLE TO UPDATE: DATA RECORD NOT FOUND"}


def get_id_types(id):
    results = []
    try:
        results.append(ObjectId(id))
    except:
        pass
    results = results + [id, str(id)]
    try:
        results.append(float(id))
    except:
        pass
    try:
        results.append(int(float(str(id))))
    except:
        pass
    # print results
    return results
