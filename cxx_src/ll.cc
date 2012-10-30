#include <ilias/net2/ll.h>


namespace ilias {
namespace ll_detail {


/* Find the successor of this node. */
RVALUE(pointer_flag)
hook_ptr::succ() const ILIAS_NET2_NOTHROW
{
	pointer_flag s = (*this)->m_succ.get();
	if (!s.first)
		return MOVE(s);

	while (s.first.deleted()) {
		hook_ptr ss = s.first->m_succ.get().first;
		if ((*this)->m_succ.compare_exchange(s, ss))
			s.first = MOVE(ss);
		else
			s = (*this)->m_succ.get();
	}
	return MOVE(s);
}

/* Find the predecessor of this node. */
RVALUE(pointer_flag)
hook_ptr::pred() const ILIAS_NET2_NOTHROW
{
	pointer_flag p = (*this)->m_pred.get();
	if (!p.first)
		return MOVE(p);

	for (;;) {
		/* Move forward until p is the direct successor of this. */
		hook_ptr ps;
		while (!p.second /* p.second => this->deleted() */ &&
		    (ps = p.first.succ().first) != this->get()) {
			if ((*this)->m_pred.compare_exchange(p, ps))
				p.first = ps;
			else
				p = (*this)->m_pred.get();
		}

		/* p is a direct successor and hopefully not deleted. */
		if (!p.first.deleted())
			return MOVE(p);

		/* Move to predecessor of p, since p is deleted. */
		hook_ptr pp = p.first->m_pred.get().first;
		if ((*this)->m_pred.compare_exchange(p, pp))
			p.first = pp;
		else
			p = (*this)->m_pred.get();
	}
}

std::size_t
hook_ptr::succ_end_distance(const hook* end) const ILIAS_NET2_NOTHROW
{
	size_t dist = 0;

	for (hook_ptr i = *this;
	    i != end;
	    i = MOVE(i->m_succ.get().first)) {
		if (!i.deleted())
			++dist;
	}
	return dist;
}

bool
hook_ptr::unlink_nowait() const ILIAS_NET2_NOTHROW
{
	for (;;) {
		/* Read predecessor. */
		pointer_flag p = this->pred();
		if (!p.first || p.second)
			return false; /* Someone else is unlinking. */

		/* Acquire predecessor, iff its successor points at this. */
		ll_ptr::deref_lock<ll_ptr> lck(p.first->m_succ, false);
		if (!lck.lock_conditional(this->get()))
			continue; /* pred() changed. */

		/* Mark this for deletion (by setting m_pred to flagged). */
		if (!(*this)->m_pred.compare_exchange(p, pointer_flag(p.first, true))) {
			if (!p.first || p.second)
				return false; /* Someone else is unlinking. */
			continue; /* Restart attempt to unlink. */
		}

		/* Unlock predecessor. */
		lck.unlock();

		/* Update predecessor to skip this. */
		p.first.succ();

		return true;
	}
}

void
hook_ptr::unlink_wait(const hook& list_head) const ILIAS_NET2_NOTHROW
{
	for (hook_ptr s = MOVE(this->succ().first);
	    (*this)->m_refcnt.load(std::memory_order_relaxed) > 1 && s != &list_head;
	    s = MOVE(s.succ().first)) {
		if (s->m_pred.get_ptr() == *this)
			s.pred(); /* Fix predecessor. */
	}

	while ((*this)->m_refcnt.load(std::memory_order_relaxed) > 1) {
		//SPINWAIT();
	}

	const pointer_flag clear(hook_ptr(), false);
	(*this)->m_succ.exchange(clear);
	(*this)->m_pred.exchange(clear);
}

bool
hook_ptr::unlink(const hook& list_head) const ILIAS_NET2_NOTHROW
{
	if (!unlink_nowait())
		return false;
	this->unlink_wait(list_head);
	return true;
}

list::simple_iterator&
list::first(list::simple_iterator& v) const ILIAS_NET2_NOTHROW
{
	hook_ptr headnode = const_cast<hook*>(&this->m_head);
	hook_ptr element = headnode.succ().first;
	v.reset(MOVE(headnode), MOVE(element));
	return v;
}

list::simple_iterator&
list::last(list::simple_iterator& v) const ILIAS_NET2_NOTHROW
{
	hook_ptr headnode = const_cast<hook*>(&this->m_head);
	hook_ptr element = headnode.pred().first;
	v.reset(MOVE(headnode), MOVE(element));
	return v;
}

list::simple_iterator&
list::listhead(list::simple_iterator& v) const ILIAS_NET2_NOTHROW
{
	hook_ptr headnode = const_cast<hook*>(&this->m_head);
	v.reset(MOVE(headnode));
	return v;
}

hook*
list::pop_front() ILIAS_NET2_NOTHROW
{
	hook_ptr i = &this->m_head;
	for (i = MOVE(i.succ().first); i != &this->m_head; i = MOVE(i.succ().first)) {
		if (i.unlink(this->m_head))
			return i.get();
	}
	return nullptr;
}

hook*
list::pop_back() ILIAS_NET2_NOTHROW
{
	hook_ptr i = &this->m_head;
	for (i = MOVE(i.pred().first); i != &this->m_head; i = MOVE(i.pred().first)) {
		if (i.unlink(this->m_head))
			return i.get();
	}
	return nullptr;
}

void
list::simple_iterator::step_forward() ILIAS_NET2_NOTHROW
{
	element = MOVE(element.succ().first);
	if (element == listhead)
		element.reset();
}

void
list::simple_iterator::step_backward() ILIAS_NET2_NOTHROW
{
	element = MOVE(element.pred().first);
	if (element == listhead)
		element.reset();
}


}} /* namespace ilias::ll_detail */
