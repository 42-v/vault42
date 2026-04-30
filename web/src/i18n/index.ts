import type { LocaleMessages } from '@vault42/vue'

import en from '../locales/en.json'
import sk from '../locales/sk.json'
import hu from '../locales/hu.json'
import de from '../locales/de.json'
import fr from '../locales/fr.json'
import es from '../locales/es.json'
import pt from '../locales/pt.json'
import it from '../locales/it.json'
import nl from '../locales/nl.json'
import pl from '../locales/pl.json'
import cs from '../locales/cs.json'
import ro from '../locales/ro.json'
import bg from '../locales/bg.json'
import hr from '../locales/hr.json'
import sr from '../locales/sr.json'
import sl from '../locales/sl.json'
import uk from '../locales/uk.json'
import ru from '../locales/ru.json'
import tr from '../locales/tr.json'
import el from '../locales/el.json'
import ar from '../locales/ar.json'
import he from '../locales/he.json'
import ja from '../locales/ja.json'
import ko from '../locales/ko.json'
import zhHans from '../locales/zh-Hans.json'
import zhHant from '../locales/zh-Hant.json'
import hi from '../locales/hi.json'
import th from '../locales/th.json'
import vi from '../locales/vi.json'
import id from '../locales/id.json'
import ms from '../locales/ms.json'
import fi from '../locales/fi.json'
import sv from '../locales/sv.json'
import da from '../locales/da.json'
import no from '../locales/no.json'
import et from '../locales/et.json'
import lv from '../locales/lv.json'
import lt from '../locales/lt.json'

export const messages: Record<string, LocaleMessages> = {
  en, sk, hu, de, fr, es, pt, it, nl, pl, cs, ro, bg, hr, sr, sl,
  uk, ru, tr, el, ar, he, ja, ko,
  'zh-Hans': zhHans,
  'zh-Hant': zhHant,
  hi, th, vi, id, ms, fi, sv, da, no, et, lv, lt,
}

export { detectLocale } from './detection'
