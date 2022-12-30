import { map_get_num_items, map_get_item_key, map_get_item_key_length, map_get_item_integer_key, map_get_item, map_init, map_add, map_add_integer } from "./functions.js"

export function fromWallyMap(wally_map) {
    const js_map = new Map, map_len = map_get_num_items(wally_map)

    for (let i = 0; i < map_len; i++) {
        const is_int_key = map_get_item_key_length(wally_map, i) == 0
            , key = is_int_key ? map_get_item_integer_key(wally_map, i)
                               : map_get_item_key(wally_map, i).toString()
        js_map.set(key, map_get_item(wally_map, i))
    }

    return js_map
}

export function toWallyMap(js_map) {
    if (js_map && js_map.constructor == Object) {
        // Convert plain objects into a Map
        js_map = new Map(Object.entries(js_map))
    } else if (!(js_map instanceof Map)) {
        throw new Error('Invalid map for toWallyMap')
    }

    const wally_map = map_init(js_map.size, null)

    js_map.forEach((val, key) => {
        val = Buffer.from(val)
        if (typeof key == 'number') {
            map_add_integer(wally_map, key, val)
        } else {
            map_add(wally_map, Buffer.from(key), val)
        }
    })

    return wally_map
}