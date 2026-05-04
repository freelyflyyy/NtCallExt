#pragma once

namespace NtExt {

	template<typename T>
	struct RemoveReference {
		using Type = T;
	};

	template<typename T>
	struct RemoveReference<T&> {
		using Type = T;
	};

	template<typename T>
	struct RemoveReference<T&&> {
		using Type = T;
	};

	template<typename F>
	class ScopeAction {
		public:
		template<typename U>
		explicit ScopeAction(U&& action) noexcept :
			_action(static_cast<U&&>(action)),
			_active(true) {
		}

		ScopeAction(ScopeAction&& other) noexcept : 
			_action(static_cast<F&&>(other._action)),
			_active(other._active) {
			other.Cancel();
		}

		~ScopeAction() noexcept {
			if ( _active ) {
				_action();
			}
		}

		void Cancel() noexcept {
			_active = false;
		}

		ScopeAction(const ScopeAction&) = delete;
		ScopeAction& operator=(const ScopeAction&) = delete;
		ScopeAction& operator=(ScopeAction&&) = delete;

		private:
		F _action;
		bool _active;
	};

	template<typename U>
	ScopeAction<typename RemoveReference<U>::Type>
		MakeScopeAction(U&& action) noexcept {
		using ActionType = typename RemoveReference<U>::Type;
		return ScopeAction<ActionType>(static_cast<U&&>(action));
	}

	struct ScopeActionBuilder {
		template<typename U>
		ScopeAction<typename RemoveReference<U>::Type>
			operator+(U&& action) const noexcept {
			using ActionType = typename RemoveReference<U>::Type;

			return ScopeAction<ActionType>(static_cast<U&&>(action));
		}
	};
}

#define NTEXT_CONCAT_IMPL(x, y) x##y
#define NTEXT_CONCAT(x, y) NTEXT_CONCAT_IMPL(x, y)

#define NTEXT_SCOPE_ACTION(action) \
	::NtExt::MakeScopeAction(action)

#define NTEXT_DEFER \
	auto NTEXT_CONCAT(ntextScopeAction, __COUNTER__) = \
		::NtExt::ScopeActionBuilder() + [&]() noexcept
