# Time zone picker assets

 - `tz-map.svg`: an equirectangular map of the world's land, 4 units a degree,
   from 180W, and from 84N down to 60S, leaving out Antarctica, with a dot at
   the principal city of each time zone in tzdata's `zone1970.tab`

 - `tz-zones.h`: those zones as a C table, with where their city is and their
   POSIX TZ string, for `lws_tz_at()` (`lws-tz.h`), and the map's projection,
   so a press on the map can be turned into somewhere on earth

They're made by `gen-tz.py`, from Natural Earth's 1:110m land polygons and
tzdata, both public domain.  It isn't run by the build: run it again and check
the results in when tzdata changes.

```
 $ curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_land.geojson
 $ python3 -I gen-tz.py ne_110m_land.geojson /usr/share/zoneinfo .
```

The lhp example's time zone page uses them, see
`minimal-examples/embedded/lhp/README.md`.
